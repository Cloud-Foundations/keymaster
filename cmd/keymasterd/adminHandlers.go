package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
)

const usersPath = "/users/"
const addUserPath = "/admin/addUser"
const deleteUserPath = "/admin/deleteUser"
const generateBoostrapOTPPath = "/admin/newboostrapOTP"

const defaultBootstrapOTPDuration = 6 * time.Hour

/*
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
*/

func (state *RuntimeState) usersHandler(w http.ResponseWriter,
	r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	failure, authUser := state.sendFailureToClientIfNonAdmin(w, r)
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

/*
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
*/
func (state *RuntimeState) sendFailureToClientIfNonAdmin(
	w http.ResponseWriter, r *http.Request) (bool, string) {
	if state.sendFailureToClientIfLocked(w, r) {
		return true, ""
	}
	authUser, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		state.writeFailureResponse(w, r, http.StatusUnauthorized, err.Error())
		return false, ""
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	if state.IsAdminUser(authUser) {
		return authUser
	}
	state.writeFailureResponse(w, r, http.StatusUnauthorized, "Not admin user")
	return ""
}

/*
func (state *RuntimeState) addUserHandler(w http.ResponseWriter,
	r *http.Request) {
	username := state.checkAdminAndGetUsername(w, r)
	if username == "" {
=======
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return true, ""
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	if !state.IsAdminUser(authUser) {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return true, ""
	}
	return false, authUser
}
*/

func (state *RuntimeState) addUsersHandler(
	w http.ResponseWriter, r *http.Request) {
	if failure, _ := state.sendFailureToClientIfNonAdmin(w, r); failure {
		return
	}
	//TODO: check method, must be POST
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
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
	if failure, _ := state.sendFailureToClientIfNonAdmin(w, r); failure {
		return
	}
	//TODO: check method, must be POST
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
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

func (state *RuntimeState) generateBootstrapOTP(
	w http.ResponseWriter, r *http.Request) {
	failure, authUser := state.sendFailureToClientIfNonAdmin(w, r)
	if failure {
		return
	}
	//TODO: check method, must be POST
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	err := r.ParseForm()
	if err != nil {
		logger.Printf("error parsing err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}

	//check username
	inputUsers, ok := r.Form["username"]
	if !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Required Parameters missing (username)")
		return
	}
	if len(inputUsers) != 1 {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "TooManyUsers")
		return
	}
	username := inputUsers[0]
	profile, existing, fromCache, err := state.LoadUserProfile(username)
	if err != nil {
		logger.Printf("error parsing err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if !existing {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "User does not exist in DB")
		return
	}
	if fromCache {
		state.writeFailureResponse(w, r, http.StatusServiceUnavailable, "Working in db disconnected mode, try again later")
		return
	}
	logger.Printf("profile=%v", profile)
	bootstrapOTP := bootstrapOTPData{
		ExpiresAt: time.Now().Add(defaultBootstrapOTPDuration),
	}
	bootstrapOTP.Value, err = genRandomString()
	if err != nil {
		logger.Printf("error generating randr=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	profile.BootstrapOTP = bootstrapOTP
	err = state.SaveUserProfile(username, profile)
	if err != nil {
		logger.Printf("error saving profile randr=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	displayData := newBootstrapOTPPPageTemplateData{
		Title:        "New Bootstrap OTP Value",
		AuthUsername: authUser,
		//JSSources         []string
		//ErrorMessage      string
		Username:          username,
		BootstrapTOTValue: bootstrapOTP.Value,
	}
	returnAcceptType := getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		err := state.htmlTemplate.ExecuteTemplate(w, "newBoostrapOTPage", displayData)
		if err != nil {
			logger.Printf("Failed to execute %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	default:
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(displayData)
	}
	return
}
