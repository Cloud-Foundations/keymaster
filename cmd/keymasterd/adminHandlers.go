package main

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
)

const usersPath = "/users/"
const addUsersPath = "/admin/adduser"
const deleteUsersPath = "/admin/deleteuser"

func (state *RuntimeState) usersHandler(
	w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	authUser, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)

	if !state.IsAdminUser(authUser) {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}

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

func (state *RuntimeState) sendFailureToClientIfNonAdmin(
	w http.ResponseWriter, r *http.Request) bool {
	if state.sendFailureToClientIfLocked(w, r) {
		return true
	}
	authUser, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return true
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	if !state.IsAdminUser(authUser) {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return true
	}
	return false
}

func (state *RuntimeState) addUsersHandler(
	w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfNonAdmin(w, r) {
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
	usersToAdd, ok := r.Form["username"]
	if !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Required Parameters missing")
		return
	}
	//It is a good idea to match?
	for _, username := range usersToAdd {
		matched, err := regexp.Match(`^[A-Za-z0-9-_.]+$`, []byte(username))
		if err != nil {
			logger.Printf("error parsing err=%s", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		if !matched {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Usernames found")
			return
		}
	}
	var newProfiles map[string]*userProfile
	newProfiles = make(map[string]*userProfile)
	//check if usernames already exist
	for _, username := range usersToAdd {
		profile, existing, fromCache, err := state.LoadUserProfile(username)
		if err != nil {
			logger.Printf("error parsing err=%s", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		if existing {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "User exist in DB")
			return
		}
		if fromCache {
			state.writeFailureResponse(w, r, http.StatusServiceUnavailable, "Working in db disconnected mode, try again later")
			return
		}
		newProfiles[username] = profile
	}
	for username, userProfile := range newProfiles {
		err := state.SaveUserProfile(username, userProfile)
		if err != nil {
			logger.Printf("error Savinf Profile  err=%s", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
	}
	//if html then redirect to users page, else return jsonOK
	preferredAcceptType := getPreferredAcceptType(r)
	switch preferredAcceptType {
	case "text/html":

		http.Redirect(w, r, usersPath, http.StatusFound)
	default:
		w.WriteHeader(200)
		fmt.Fprintf(w, "OK\n")
	}
}

func (state *RuntimeState) deleteUsersHandler(
	w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfNonAdmin(w, r) {
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
	usersToDelete, ok := r.Form["username"]
	if !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Required Parameters missing")
		return
	}
	for _, username := range usersToDelete {
		err = state.DeleteUserProfile(username)
		if err != nil {
			logger.Printf("error parsing err=%s", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
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
