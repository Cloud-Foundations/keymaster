package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

const bootstrapOtpAuthPath = "/api/v0/bootstrapOtpAuth"

func (state *RuntimeState) BootstrapOtpAuthHandler(w http.ResponseWriter,
	r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	switch r.Method {
	case "GET":
		state.logger.Debugf(3, "Got client GET connection")
		if err := r.ParseForm(); err != nil {
			state.logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Error parsing form")
			return
		}
	case "POST":
		state.logger.Debugf(3, "Got client POST connection")
		if err := r.ParseForm(); err != nil {
			state.logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Error parsing form")
			return
		}
	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	authUser, currentAuthLevel, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		state.logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	var inputOTP string
	if val, ok := r.Form["OTP"]; ok {
		if len(val) > 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Just one OTP Value allowed")
			state.logger.Printf("Login with multiple OTP Values")
			return
		}
		inputOTP = val[0]
	}
	requiredOTP := state.userBootstrapOtp(authUser)
	if requiredOTP == "" {
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed,
			"No valid Bootstrap OTP saved")
		return
	}
	if inputOTP != requiredOTP {
		state.logger.Printf("Invalid Bootstrap OTP value for %s\n",
			authUser)
		state.logger.Debugf(0, "  input: \"%s\" required: \"%s\"\n",
			inputOTP, requiredOTP)
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"Invalid Bootstrap OTP")
		return
	}
	profile, _, fromCache, err := state.LoadUserProfile(authUser)
	if err != nil {
		state.logger.Printf("error parsing err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if fromCache {
		state.writeFailureResponse(w, r, http.StatusServiceUnavailable,
			"Working in DB disconnected mode, try again later")
		return
	}
	profile.BootstrapOTP = bootstrapOTPData{}
	if err := state.SaveUserProfile(authUser, profile); err != nil {
		state.logger.Printf("error saving profile randr=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	_, err = state.updateAuthCookieAuthlevel(w, r,
		currentAuthLevel|AuthTypeBootstrapOTP)
	if err != nil {
		logger.Printf("Auth Cookie NOT found ? %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"Failure when validating Boostrap OTP")
		return
	}
	// eventNotifier.PublishBootstrapOtpAuthEvent(eventmon.AuthTypeBootstrapOTP,
	// authUser)
	// Now we send the user to the appropriate place
	returnAcceptType := getPreferredAcceptType(r)
	// TODO: The cert backend should depend also on per user preferences.
	loginResponse := proto.LoginResponse{Message: "success"}
	switch returnAcceptType {
	case "text/html":
		loginDestination := getLoginDestination(r)
		eventNotifier.PublishWebLoginEvent(authUser)
		state.logger.Debugf(0, "redirecting to: %s\n", loginDestination)
		http.Redirect(w, r, loginDestination, 302)
	default:
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(loginResponse)
	}
}

func (state *RuntimeState) userBootstrapOtp(username string) string {
	profile, _, fromCache, err := state.LoadUserProfile(username)
	state.logger.Debugf(1, "userBootstrapOtp: username: %s, fromCache: %v\n",
		username, fromCache)
	if err != nil {
		return ""
	}
	if len(profile.U2fAuthData) > 0 {
		return ""
	}
	if fromCache { // Since we will want to clear the OTP, require connection.
		return ""
	}
	if profile.BootstrapOTP.Value == "" {
		return ""
	}
	if time.Since(profile.BootstrapOTP.ExpiresAt) >= 0 {
		return ""
	}
	return profile.BootstrapOTP.Value
}
