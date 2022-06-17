package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tstranex/u2f"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/proto/eventmon"
)

/*
+func u2fAuthDataToWebauthnCred(authData u2fAuthData) (*webauthn.Credential, error) {
+       pubKeyBytes := elliptic.Marshal(authData.Registration.PubKey.Curve, authData.Registration.PubKey.X, authData.Registration.PubKey.Y)
+       credential := webauthn.Credential{
+               AttestationType: "fido-u2f",
+               ID:              u2fAuthData.Registration.KeyHandle,
+               PublicKey:       pubKeyBytes,
+               Authenticator: webauthn.Authenticator{
+                       // The AAGUID of the authenticator. An AAGUID is defined as an array containing the globally unique
+                       // identifier of the authenticator model being sought.
+                       AAGUID:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
+                       SignCount: authData.Counter,
+               },
+       }
+       return &credential, nil
+}

*/

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func webauthnJsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	logger.Debugf(3, "webauth json response=%s", dj)
	fmt.Fprintf(w, "%s", dj)
}

const webAutnRegististerRequestPath = "/webauthn/RegisterRequest/"

// RegisterRequest?
func (state *RuntimeState) webauthnBeginRegistration(w http.ResponseWriter, r *http.Request) {
	logger.Debugf(3, "top of webauthnBeginRegistration")
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
		logger.Debugf(1, "webauthnBeginRegistration: bad number of pieces")
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
		logger.Printf("webauthnBeginRegistration: loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
		return
	}

	profile.FixupCredential(assumedUser, assumedUser)
	logger.Debugf(2, "webauthnBeginRegistration profile=%+v", profile)

	/*
		authSelect := protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
			RequireResidentKey:      protocol.ResidentKeyUnrequired(),
			// We use unrequired https://chromium.googlesource.com/chromium/src/+/master/content/browser/webauth/uv_preferred.md
			UserVerification: protocol.VerificationDiscouraged,
		}
	*/

	// Updating the ConveyencePreference options.
	// See the struct declarations for values
	//conveyencePref := protocol.ConveyancePreference(protocol.PreferNoAttestation)

	logger.Debugf(2, "webauthnBeginRegistration: About to begin BeginRegistration")
	//options, sessionData, err := state.webAuthn.BeginRegistration(profile)
	options, sessionData, err := state.webAuthn.BeginRegistration(profile)
	//webauthn.WithAuthenticatorSelection(authSelect))
	//webauthn.WithConveyancePreference(conveyencePref))
	if err != nil {
		state.logger.Printf("webauthnBeginRegistration: begin login failed %s", err)
		// TODO: we should not be sending ALL the errors to clients
		webauthnJsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profile.WebauthnSessionData = sessionData
	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	webauthnJsonResponse(w, options, http.StatusOK)
}

const webAutnRegististerFinishPath = "/webauthn/RegisterFinish/"

func (state *RuntimeState) webauthnFinishRegistration(w http.ResponseWriter, r *http.Request) {
	logger.Debugf(3, "top of webauthnFinishRegistration")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// TODO: better pattern matching
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

	// load the session data
	credential, err := state.webAuthn.FinishRegistration(profile, *profile.WebauthnSessionData, r)
	if err != nil {
		state.logger.Println(err)
		webauthnJsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	logger.Debugf(2, "new credential=%+v\n", *credential)

	err = profile.AddWebAuthnCredential(*credential)
	if err != nil {
		logger.Printf("Saving adding credential error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	webauthnJsonResponse(w, "Registration Success", http.StatusOK)
}

//
const webAuthnAuthBeginPath = "/webauthn/AuthBegin/"

func (state *RuntimeState) webauthnAuthLogin(w http.ResponseWriter, r *http.Request) {
	logger.Debugf(3, "top of webauthnAuthBegin")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	profile, _, fromCache, err := state.LoadUserProfile(authData.Username)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		logger.Debugf(1, "DB is being cached and requesting authentication, proceeding with cached values")
	}

	////
	// TODO: there is an extension to ensure it is an actual secirity key... need to add this to the call.
	extensions := protocol.AuthenticationExtensions{"appid": u2fAppID}
	options, sessionData, err := state.webAuthn.BeginLogin(profile,
		webauthn.WithAssertionExtensions(extensions))
	if err != nil {
		logger.Printf("webauthnAuthBegin: %s", err)
		webauthnJsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	c, err := u2f.NewChallenge(u2fAppID, u2fTrustedFacets)
	if err != nil {
		logger.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	c.Challenge, err = base64.RawURLEncoding.DecodeString(sessionData.Challenge)
	if err != nil {
		logger.Printf("webauthnAuthBegin base64  error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	var localAuth localUserData
	localAuth.U2fAuthChallenge = c
	localAuth.WebAuthnChallenge = sessionData
	localAuth.ExpiresAt = time.Now().Add(maxAgeU2FVerifySeconds * time.Second)
	state.Mutex.Lock()
	state.localAuthData[authData.Username] = localAuth
	state.Mutex.Unlock()

	webauthnJsonResponse(w, options, http.StatusOK)
	logger.Debugf(3, "end of webauthnAuthBegin")
}

//
const webAuthnAuthFinishPath = "/webauthn/AuthFinish/"

func (state *RuntimeState) webauthnAuthFinish(w http.ResponseWriter, r *http.Request) {
	logger.Debugf(3, "top of webauthnAuthFinish")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	profile, ok, _, err := state.LoadUserProfile(authData.Username)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if !ok {
		http.Error(w, "No regstered data", http.StatusBadRequest)
		return
	}

	state.Mutex.Lock()
	localAuth, ok := state.localAuthData[authData.Username]
	state.Mutex.Unlock()
	if !ok {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		logger.Printf("Error parsing Response")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	userCredentials := profile.WebAuthnCredentials()
	var loginCredential webauthn.Credential
	var credentialFound bool
	var credentialIndex int64
	for _, cred := range userCredentials {
		if cred.AttestationType != "fido-u2f" {
			continue
		}
		if bytes.Equal(cred.ID, parsedResponse.RawID) {
			loginCredential = cred
			credentialFound = true
			for i, u2fReg := range profile.U2fAuthData {
				if !u2fReg.Enabled {
					continue
				}
				if bytes.Equal(u2fReg.Registration.KeyHandle, parsedResponse.RawID) {
					credentialIndex = i
				}
			}

			break
		}
		credentialFound = false
	}

	verifiedAuth := authData.AuthType
	if !credentialFound {
		// DO STD webaautn verification
		_, err = state.webAuthn.ValidateLogin(profile, *localAuth.WebAuthnChallenge, parsedResponse) // iFinishLogin(profile, *localAuth.WebAuthnChallenge, r)
		if err != nil {
			logger.Printf("webauthnAuthFinish: auth failure err=%s", err)
			webauthnJsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO also update the profile with latest counter
		verifiedAuth = AuthTypeFIDO2
	} else {
		// NOTE: somehow the extensions for grabbing the appID are failing
		// So we "unroll" the important pieces of webAuthn.ValidateLogin here, with
		// explicit changes for our appID
		// Notice that if we where strict we would iterate over all the alloowed values.
		session := *localAuth.WebAuthnChallenge
		shouldVerifyUser := session.UserVerification == protocol.VerificationRequired

		rpID := state.webAuthn.Config.RPID
		rpOrigin := state.webAuthn.Config.RPOrigin
		appID := u2fAppID

		// Handle steps 4 through 16
		validError := parsedResponse.Verify(session.Challenge, rpID, rpOrigin, appID, shouldVerifyUser, loginCredential.PublicKey)
		if validError != nil {
			logger.Printf("failed to verify webauthn parsedResponse")
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "Credential Not Found")
			return
		}

		//loginCredential.Authenticator.UpdateCounter(parsedResponse.Response.AuthenticatorData.Counter)
		u2fReg, ok := profile.U2fAuthData[credentialIndex]
		if ok {
			u2fReg.Counter = parsedResponse.Response.AuthenticatorData.Counter
			profile.U2fAuthData[credentialIndex] = u2fReg
			go state.SaveUserProfile(authData.Username, profile)
		}

		verifiedAuth = AuthTypeU2F
		logger.Debugf(3, "success (LOCAL)")
	}
	logger.Debugf(1, "webauthnAuthFinish: auth success")

	// TODO: disinguish better between the two protocols or just use one
	//metricLogAuthOperation(getClientType(r), proto.AuthTypeU2F, true)
	state.Mutex.Lock()
	delete(state.localAuthData, authData.Username)
	state.Mutex.Unlock()

	//TODO: distinguish here u2f vs webauthn
	eventNotifier.PublishAuthEvent(eventmon.AuthTypeU2F, authData.Username)
	_, isXHR := r.Header["X-Requested-With"]
	if isXHR {
		eventNotifier.PublishWebLoginEvent(authData.Username)
	}

	_, err = state.updateAuthCookieAuthlevel(w, r,
		authData.AuthType|verifiedAuth|AuthTypeU2F)
	if err != nil {
		logger.Printf("Auth Cookie NOT found ? %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure updating vip token")
		return
	}
	webauthnJsonResponse(w, "Login Success", http.StatusOK)
}
