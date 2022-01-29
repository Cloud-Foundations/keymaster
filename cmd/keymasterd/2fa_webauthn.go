package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	//"github.com/duo-labs/webauthn/webauthn"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
)

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func webauthnJsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
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

	logger.Debugf(2, "webauthnBeginRegistration: About to begin BeginRegistration")
	options, sessionData, err := state.webAuthn.BeginRegistration(profile)
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
		logger.Printf("DB is being cached and requesting authentication, proceeding with cached values")
		//http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
		//return
	}

	////
	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := state.webAuthn.BeginLogin(profile)
	if err != nil {
		logger.Printf("webauthnAuthBegin: %s", err)
		webauthnJsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var localAuth localUserData
	localAuth.WebAuthnChallenge = sessionData
	localAuth.ExpiresAt = time.Now().Add(maxAgeU2FVerifySeconds * time.Second)
	state.Mutex.Lock()
	state.localAuthData[authData.Username] = localAuth
	state.Mutex.Unlock()
	/*
		// store session data as marshaled JSON
		err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
		if err != nil {
			log.Println(err)
			jsonResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonResponse(w, options, http.StatusOK)
	*/
	webauthnJsonResponse(w, options, http.StatusOK)
}

//
const webAuthnAuthFinishPath = "/webauthn/AuthFinish/"

func (state *RuntimeState) webauthnAuthFinish(w http.ResponseWriter, r *http.Request) {
	logger.Debugf(3, "top of webauthnAuthBegin")
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

	/*
	   // load the session data
	        sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	        if err != nil {
	                log.Println(err)
	                jsonResponse(w, err.Error(), http.StatusBadRequest)
	                return
	        }
	*/

	state.Mutex.Lock()
	localAuth, ok := state.localAuthData[authData.Username]
	state.Mutex.Unlock()
	if !ok {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}

	/*
	       // in an actual implementation we should perform additional
	       // checks on the returned 'credential'
	   	_, err = webAuthn.FinishLogin(user, sessionData, r)
	   	if err != nil {
	   		log.Println(err)
	   		jsonResponse(w, err.Error(), http.StatusBadRequest)
	   		return
	   	}

	   	// handle successful login
	   	jsonResponse(w, "Login Success", http.StatusOK)
	*/

	// in an actual implementation we should perform additional
	// checks on the returned 'credential'
	_, err = state.webAuthn.FinishLogin(profile, *localAuth.WebAuthnChallenge, r)
	if err != nil {
		logger.Println(err)
		webauthnJsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	//metricLogAuthOperation(getClientType(r), proto.AuthTypeU2F, true)
	/*
	   logger.Debugf(0, "newCounter: %d", newCounter)
	   u2fReg.Counter = newCounter
	   profile.U2fAuthData[i] = u2fReg
	*/
	state.Mutex.Lock()
	delete(state.localAuthData, authData.Username)
	state.Mutex.Unlock()

	/*
		eventNotifier.PublishAuthEvent(eventmon.AuthTypeU2F, authData.Username)
		_, isXHR := r.Header["X-Requested-With"]
		if isXHR {
			eventNotifier.PublishWebLoginEvent(authData.Username)
		}
	*/
	_, err = state.updateAuthCookieAuthlevel(w, r,
		authData.AuthType|AuthTypeFIDO2)
	if err != nil {
		logger.Printf("Auth Cookie NOT found ? %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure updating vip token")
		return
	}

	webauthnJsonResponse(w, "Login Success", http.StatusOK)

}
