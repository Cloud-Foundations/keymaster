package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/Cloud-Foundations/keymaster/proto/eventmon"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/tstranex/u2f"
)

func webauthnRegistrationToU2fRegistration(reg webauthAuthData) (*u2fAuthData, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), reg.Credential.PublicKey)
	if x == nil || y == nil {
		logger.Debugf(0, "cannot decode not native p256 curve")
		cosePubkey, err := webauthncose.ParsePublicKey(reg.Credential.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("not a webcose pub key either")
		}
		logger.Debugf(0, "it is a cosePubkey of type %T ", cosePubkey)

		coseECKey, ok := cosePubkey.(webauthncose.EC2PublicKeyData)
		if !ok {
			return nil, fmt.Errorf("not an Cose EC2PublicKeyData")
		}
		if webauthncose.COSEAlgorithmIdentifier(coseECKey.Algorithm) != webauthncose.AlgES256 {
			return nil, fmt.Errorf("not a P256 curve")
		}
		x = big.NewInt(0).SetBytes(coseECKey.XCoord)
		y = big.NewInt(0).SetBytes(coseECKey.YCoord)
		logger.Debugf(2, "webauthnRegistrationToU2fRegistration: cose p256 curve found")
	}
	registration := u2f.Registration{
		KeyHandle: reg.Credential.ID,
		PubKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
	}
	authData := u2fAuthData{
		Registration: &registration,
		Counter:      reg.Credential.Authenticator.SignCount,
	}
	return &authData, nil
}

func (u *userProfile) getRegistrationArray() (regArray []u2f.Registration) {
	for _, data := range u.U2fAuthData {
		if !data.Enabled {
			continue
		}
		regArray = append(regArray, *data.Registration)
	}
	for _, webauth := range u.WebauthnData {
		if !webauth.Enabled {
			continue
		}
		u2fData, err := webauthnRegistrationToU2fRegistration(*webauth)
		if err != nil {
			logger.Debugf(3, " getRegistrationArray could not transform webauth err:%s", err)
			continue
		}
		regArray = append(regArray, *u2fData.Registration)
	}
	return regArray
}

const u2fRegustisterRequestPath = "/u2f/RegisterRequest/"

func (state *RuntimeState) u2fRegisterRequest(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// /u2f/RegisterRequest/<assumed user>
	// pieces[0] == "" pieces[1] = "u2f" pieces[2] == "RegisterRequest"
	pieces := strings.Split(r.URL.Path, "/")

	var assumedUser string
	if len(pieces) >= 4 {
		assumedUser = pieces[3]
	} else {
		http.Error(w, "error", http.StatusBadRequest)
		return
	}

	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	// Check that they can change other users
	if !state.IsAdminUserAndU2F(authData.Username, authData.AuthType) &&
		authData.Username != assumedUser {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
		return
	}

	c, err := u2f.NewChallenge(u2fAppID, u2fTrustedFacets)
	if err != nil {
		logger.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	profile.RegistrationChallenge = c
	registrations := profile.getRegistrationArray()
	req := u2f.NewWebRegisterRequest(c, registrations)

	logger.Printf("registerRequest: %+v", req)
	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(req)
}

const u2fRegisterRequesponsePath = "/u2f/RegisterResponse/"

func (state *RuntimeState) u2fRegisterResponse(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// /u2f/RegisterResponse/<assumed user>
	// pieces[0] == "" pieces[1] = "u2f" pieces[2] == "RegisterResponse"
	pieces := strings.Split(r.URL.Path, "/")

	var assumedUser string
	if len(pieces) >= 4 {
		assumedUser = pieces[3]
	} else {
		http.Error(w, "error", http.StatusBadRequest)
		return
	}

	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	// Check that they can change other users
	if !state.IsAdminUserAndU2F(authData.Username, authData.AuthType) &&
		authData.Username != assumedUser {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var regResp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
		return
	}

	if profile.RegistrationChallenge == nil {
		http.Error(w, "challenge not found", http.StatusBadRequest)
		return
	}

	// TODO: use yubikey or get the feitan cert :(
	u2fConfig := u2f.Config{SkipAttestationVerify: true}

	reg, err := u2f.Register(regResp, *profile.RegistrationChallenge, &u2fConfig)
	if err != nil {
		logger.Printf("u2f.Register error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}

	newReg := u2fAuthData{Counter: 0,
		Registration: reg,
		Enabled:      true,
		CreatedAt:    time.Now(),
		CreatorAddr:  r.RemoteAddr,
	}
	if authData.Username != assumedUser {
		newReg.Name = fmt.Sprintf("Registered by %s", authData.Username)
	}
	newIndex := newReg.CreatedAt.Unix()
	profile.U2fAuthData[newIndex] = &newReg
	logger.Printf("Registration success: %+v", reg)
	profile.RegistrationChallenge = nil
	profile.UserHasRegistered2ndFactor = true
	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("success"))
}

const u2fSignRequestPath = "/u2f/SignRequest"

func (state *RuntimeState) u2fSignRequest(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	//////////
	profile, ok, _, err := state.LoadUserProfile(authData.Username)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	/////////
	if !ok {
		http.Error(w, "No registered data", http.StatusBadRequest)
		return
	}
	registrations := profile.getRegistrationArray()
	if len(registrations) < 1 {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	c, err := u2f.NewChallenge(u2fAppID, u2fTrustedFacets)
	if err != nil {
		logger.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	//save cached copy
	var localAuth localUserData
	localAuth.U2fAuthChallenge = c
	localAuth.ExpiresAt = time.Now().Add(maxAgeU2FVerifySeconds * time.Second)
	state.Mutex.Lock()
	state.localAuthData[authData.Username] = localAuth
	state.Mutex.Unlock()

	req := c.SignRequest(registrations)
	logger.Debugf(3, "Sign request: %+v", req)

	if err := json.NewEncoder(w).Encode(req); err != nil {
		logger.Printf("json encofing error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

const u2fSignResponsePath = "/u2f/SignResponse"

func (state *RuntimeState) u2fSignResponse(w http.ResponseWriter, r *http.Request) {
	// User must be logged in
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	//now the actual work
	var signResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	logger.Debugf(1, "signResponse: %+v", signResp)

	profile, ok, _, err := state.LoadUserProfile(authData.Username)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}

	/////////
	if !ok {
		http.Error(w, "No regstered data", http.StatusBadRequest)
		return
	}
	registrations := profile.getRegistrationArray()
	if len(registrations) < 1 {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	if registrations == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}
	state.Mutex.Lock()
	localAuth, ok := state.localAuthData[authData.Username]
	state.Mutex.Unlock()
	if !ok {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}

	//var err error
	for i, u2fReg := range profile.U2fAuthData {
		if !u2fReg.Enabled {
			continue
		}
		newCounter, authErr := u2fReg.Registration.Authenticate(signResp, *localAuth.U2fAuthChallenge, u2fReg.Counter)
		if authErr == nil {
			metricLogAuthOperation(getClientType(r), proto.AuthTypeU2F, true)

			logger.Debugf(0, "newCounter: %d", newCounter)
			//counter = newCounter
			u2fReg.Counter = newCounter
			//profile.U2fAuthData[i].Counter = newCounter
			u2fReg.Counter = newCounter
			profile.U2fAuthData[i] = u2fReg
			//profile.U2fAuthChallenge = nil
			delete(state.localAuthData, authData.Username)

			eventNotifier.PublishAuthEvent(eventmon.AuthTypeU2F, authData.Username)
			_, isXHR := r.Header["X-Requested-With"]
			if isXHR {
				eventNotifier.PublishWebLoginEvent(authData.Username)
			}
			_, err = state.updateAuthCookieAuthlevel(w, r,
				authData.AuthType|AuthTypeU2F)
			if err != nil {
				logger.Printf("Auth Cookie NOT found ? %s", err)
				state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure updating vip token")
				return
			}

			// TODO: update local cookie state
			w.Write([]byte("success"))
			return
		}
	}
	// test1: transform webahtn registration into u2f one
	for _, webauthnData := range profile.WebauthnData {
		if !webauthnData.Enabled {
			continue
		}
		u2fReg, err := webauthnRegistrationToU2fRegistration(*webauthnData)
		if err != nil {
			logger.Debugf(2, "cannot transform, err:%s", err)
			continue
		}
		newCounter, authErr := u2fReg.Registration.Authenticate(signResp, *localAuth.U2fAuthChallenge, u2fReg.Counter)
		if authErr == nil {
			metricLogAuthOperation(getClientType(r), proto.AuthTypeU2F, true)
			logger.Debugf(0, "newCounter: %d", newCounter)
			eventNotifier.PublishAuthEvent(eventmon.AuthTypeU2F, authData.Username)
			_, isXHR := r.Header["X-Requested-With"]
			if isXHR {
				eventNotifier.PublishWebLoginEvent(authData.Username)
			}
			_, err = state.updateAuthCookieAuthlevel(w, r,
				authData.AuthType|AuthTypeU2F)
			if err != nil {
				logger.Printf("Auth Cookie NOT found ? %s", err)
				state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure updating vip token")
				return
			}
			// TODO: update local cookie state
			w.Write([]byte("success"))
			return
		}
	}
	metricLogAuthOperation(getClientType(r), proto.AuthTypeU2F, false)

	logger.Printf("VerifySignResponse error: %v", err)
	http.Error(w, "error verifying response", http.StatusInternalServerError)
}
