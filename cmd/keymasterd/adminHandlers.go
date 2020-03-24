package main

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
)

const usersPath = "/users/"
const addUserPath = "/admin/addUser"
const deleteUserPath = "/admin/deleteUser"

func (state *RuntimeState) checkAdminAndGetUsername(w http.ResponseWriter,
	r *http.Request) string {
	if state.sendFailureToClientIfLocked(w, r) {
		return ""
	}
	if state.sendFailureToClientIfNonAdmin(w, r) == "" {
		return ""
	}
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return ""
	}
	err := r.ParseForm()
	if err != nil {
		logger.Printf("error parsing err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return ""
	}
	formUsername, ok := r.Form["username"]
	if !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Required Parameters missing")
		return ""
	}
	if len(formUsername) != 1 {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Single value response required")
		return ""
	}
	username := formUsername[0]
	matched, err := regexp.Match(`^[A-Za-z0-9-_.]+$`, []byte(username))
	if err != nil {
		logger.Printf("error parsing err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return ""
	}
	if !matched {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Invalid Username found")
		return ""
	}
	return username
}

func (state *RuntimeState) usersHandler(w http.ResponseWriter,
	r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	authUser := state.sendFailureToClientIfNonAdmin(w, r)
	if authUser == "" {
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	users, _, err := state.GetUsers()
	if err != nil {
		logger.Printf("Getting users error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	JSSources := []string{"/static/jquery-3.4.1.min.js"}
	displayData := usersPageTemplateData{
		AuthUsername: authUser,
		Title:        "Keymaster Users",
		Users:        users,
		JSSources:    JSSources}
	err = state.htmlTemplate.ExecuteTemplate(w, "usersPage", displayData)
	if err != nil {
		logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

// Returns empty string if an error was sent, admin username if no error.
func (state *RuntimeState) sendFailureToClientIfNonAdmin(w http.ResponseWriter,
	r *http.Request) string {
	// First check if we have a verified client certificate proving the request
	// came from an admin user.
	if r.TLS != nil {
		logger.Debugf(4, "request is TLS %+v", r.TLS)
		if len(r.TLS.VerifiedChains) > 0 {
			logger.Debugf(4, "%+v", r.TLS.VerifiedChains[0][0].Subject)
			clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
			if clientName != "" && state.IsAdminUser(clientName) {
				return clientName
			}
		}
	}
	authUser, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		state.writeFailureResponse(w, r, http.StatusUnauthorized, err.Error())
		return ""
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	if state.IsAdminUser(authUser) {
		return authUser
	}
	state.writeFailureResponse(w, r, http.StatusUnauthorized, "Not admin user")
	return ""
}

func (state *RuntimeState) addUserHandler(w http.ResponseWriter,
	r *http.Request) {
	username := state.checkAdminAndGetUsername(w, r)
	if username == "" {
		return
	}
	// Check if username already exists.
	profile, existing, fromCache, err := state.LoadUserProfile(username)
	if err != nil {
		logger.Printf("error parsing err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if existing {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"User exists in DB")
		return
	}
	if fromCache {
		state.writeFailureResponse(w, r, http.StatusServiceUnavailable,
			"Working in db disconnected mode, try again later")
		return
	}
	if err := state.SaveUserProfile(username, profile); err != nil {
		logger.Printf("error Savinf Profile  err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	// If html then redirect to users page, else return json OK.
	preferredAcceptType := getPreferredAcceptType(r)
	switch preferredAcceptType {
	case "text/html":
		http.Redirect(w, r, usersPath, http.StatusFound)
	default:
		w.WriteHeader(200)
		fmt.Fprintf(w, "OK\n")
	}
}

func (state *RuntimeState) deleteUserHandler(
	w http.ResponseWriter, r *http.Request) {
	username := state.checkAdminAndGetUsername(w, r)
	if username == "" {
		return
	}
	if err := state.DeleteUserProfile(username); err != nil {
		logger.Printf("error parsing err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	preferredAcceptType := getPreferredAcceptType(r)
	switch preferredAcceptType {
	case "text/html":
		http.Redirect(w, r, usersPath, http.StatusFound)
	default:
		w.WriteHeader(200)
		fmt.Fprintf(w, "OK\n")
	}
}
