package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

const webAutnRegustisterRequestPath = "/webauthn/RegisterRequest/"

// RegisterRequest?
func (state *RuntimeState) webauthnBeginRegistration(w http.ResponseWriter, r *http.Request) {
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

	options, sessionData, err := state.webAuthn.BeginLogin(profile)
	if err != nil {
		state.logger.Printf("%s", err)
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

func (state *RuntimeState) webauthnFinishRegistration(w http.ResponseWriter, r *http.Request) {
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
