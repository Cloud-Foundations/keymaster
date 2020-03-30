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
const generateBoostrapOTPPath = "/admin/newBoostrapOTP"

const defaultBootstrapOTPDuration = 6 * time.Hour
const maximumBootstrapOTPDuration = 24 * time.Hour

// Returns (true, "") if an error was sent, (false, adminUser) if an admin user.
func (state *RuntimeState) sendFailureToClientIfNonAdmin(w http.ResponseWriter,
	r *http.Request) (bool, string) {
	if state.sendFailureToClientIfLocked(w, r) {
		return true, ""
	}
	// TODO: probably this should be just u2f and authkeymaterx509... but
	// probably we want also to allow configurability for this. Leaving
	// AuthTypeKeymasterX509 as optional for now
	authUser, _, err := state.checkAuth(w, r,
		state.getRequiredWebUIAuthLevel()|AuthTypeKeymasterX509)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return true, ""
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	if !state.IsAdminUser(authUser) {
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"Not an admin user")
		return true, ""
	}
	return false, authUser
}

func (state *RuntimeState) ensurePostAndGetUsername(w http.ResponseWriter,
	r *http.Request) string {
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
	logger.Debugf(3, "Top of usersHandler r=%+v", r)
	failure, authUser := state.sendFailureToClientIfNonAdmin(w, r)
	if failure || authUser == "" {
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

func (state *RuntimeState) addUserHandler(w http.ResponseWriter,
	r *http.Request) {
	if failure, _ := state.sendFailureToClientIfNonAdmin(w, r); failure {
		return
	}
	username := state.ensurePostAndGetUsername(w, r)
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
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n")
	}
}

func (state *RuntimeState) deleteUserHandler(w http.ResponseWriter,
	r *http.Request) {
	if failure, _ := state.sendFailureToClientIfNonAdmin(w, r); failure {
		return
	}
	username := state.ensurePostAndGetUsername(w, r)
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
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n")
	}
}

func (state *RuntimeState) generateBootstrapOTP(w http.ResponseWriter,
	r *http.Request) {
	failure, authUser := state.sendFailureToClientIfNonAdmin(w, r)
	if failure {
		return
	}
	username := state.ensurePostAndGetUsername(w, r)
	if username == "" {
		return
	}
	profile, existing, fromCache, err := state.LoadUserProfile(username)
	if err != nil {
		state.logger.Printf("error parsing err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if !existing {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"User does not exist in DB")
		return
	}
	if fromCache {
		state.writeFailureResponse(w, r, http.StatusServiceUnavailable,
			"Working in db disconnected mode, try again later")
		return
	}
	if len(profile.U2fAuthData) > 0 || len(profile.TOTPAuthData) > 0 {
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed,
			"User has U2F tokens registered")
		return
	}
	state.logger.Debugf(1, "profile=%v", profile)
	duration := defaultBootstrapOTPDuration
	formDuration, ok := r.Form["duration"]
	if ok {
		if len(formDuration) != 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Single value duration required")
			return
		}
		duration, err = time.ParseDuration(formDuration[0])
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "")
			return
		}
	}
	if duration < time.Minute {
		duration = time.Minute
	}
	if duration > maximumBootstrapOTPDuration {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Duration over 1 day not allowed")
		return
	}
	bootstrapOTP := bootstrapOTPData{ExpiresAt: time.Now().Add(duration)}
	bootstrapOTP.Value, err = genRandomString()
	if err != nil {
		state.logger.Printf("error generating randr=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	profile.BootstrapOTP = bootstrapOTP
	err = state.SaveUserProfile(username, profile)
	if err != nil {
		state.logger.Printf("error saving profile randr=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	state.logger.Debugf(0,
		"%s: generated bootstrap OTP for: %s, duration: %s\n",
		authUser, username, duration)
	displayData := newBootstrapOTPPPageTemplateData{
		Title:        "New Bootstrap OTP Value",
		AuthUsername: authUser,
		//JSSources         []string
		//ErrorMessage      string
		Username:          username,
		BootstrapOTPValue: bootstrapOTP.Value,
	}
	returnAcceptType := getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		err := state.htmlTemplate.ExecuteTemplate(w, "newBoostrapOTPage",
			displayData)
		if err != nil {
			state.logger.Printf("Failed to execute %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	default:
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(displayData)
	}
	return
}
