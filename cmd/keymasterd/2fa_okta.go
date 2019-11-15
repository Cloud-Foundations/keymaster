package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	//"strings"
	"time"

	"github.com/Symantec/keymaster/lib/instrumentedwriter"
	"github.com/Symantec/keymaster/lib/pwauth/okta"
	"github.com/Symantec/keymaster/lib/webapi/v0/proto"
)

const okta2FAauthPath = "/api/v0/okta2FAAuth"

func (state *RuntimeState) Okta2FAuthHandler(w http.ResponseWriter, r *http.Request) {
	logger.Printf("Top of Okta2FAuthHandler")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	//authUser, authType, err := state.checkAuth(w, r, AuthTypeAny)
	authUser, currentAuthLevel, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)

	err = r.ParseForm()
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		return
	}

	var OTPString string
	if val, ok := r.Form["OTP"]; ok {
		if len(val) > 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Just one OTP Value allowed")
			logger.Printf("Login with multiple OTP Values")
			return
		}
		logger.Debugf(1, "okta handler otp Val=%+v", val)
		OTPString = val[0]
	}
	otpValue, err := strconv.Atoi(OTPString)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing OTP value")
		return
	}
	oktaAuth, ok := state.passwordChecker.(*okta.PasswordAuthenticator)
	if !ok {
		logger.Println("password authenticator is not okta")
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Apperent Misconfiguration")
		return
	}

	start := time.Now()
	valid, err := oktaAuth.ValidateUserOTP(authUser, otpValue)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating VIP token")
		return
	}

	metricLogExternalServiceDuration("okta-otp", time.Since(start))

	//
	//metricLogAuthOperation(getClientType(r), proto.AuthTypeSymantecVIP, valid)

	if !valid {
		logger.Printf("Invalid OTP value login for %s", authUser)
		// TODO if client is html then do a redirect back to vipLoginPage
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return

	}
	/*
	   // OTP check was  successful
	   logger.Debugf(1, "Successful vipOTP auth for user: %s", authUser)
	   eventNotifier.PublishVIPAuthEvent(eventmon.VIPAuthTypeOTP, authUser)
	*/
	_, err = state.updateAuthCookieAuthlevel(w, r, currentAuthLevel|AuthTypeOkta2FA)
	if err != nil {
		logger.Printf("Auth Cookie NOT found ? %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating VIP token")
		return
	}

	// Now we send to the appropiate place
	returnAcceptType := getPreferredAcceptType(r)

	// TODO: The cert backend should depend also on per user preferences.
	loginResponse := proto.LoginResponse{Message: "success"} //CertAuthBackend: certBackends
	switch returnAcceptType {
	case "text/html":
		loginDestination := getLoginDestination(r)
		eventNotifier.PublishWebLoginEvent(authUser)
		http.Redirect(w, r, loginDestination, 302)
	default:
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)
		//fmt.Fprintf(w, "Success!")
	}
	return
}

///////////////////////////
const oktaPushStartPath = "/api/v0/oktaPushStart"

func (state *RuntimeState) oktaPushStartHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if !(r.Method == "POST" || r.Method == "GET") {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	authUser, _, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)

	// TODO: check if okta 2fa is enabled

	oktaAuth, ok := state.passwordChecker.(*okta.PasswordAuthenticator)
	if !ok {
		logger.Println("password authenticator is not okta")
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Apperent Misconfiguration")
		return
	}
	pushResponse, err := oktaAuth.ValidateUserPush(authUser)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating OKTA push")
		return
	}
	switch pushResponse {
	case okta.PushResponseWaiting:
		w.WriteHeader(http.StatusOK)
		return
	default:
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "Push already sent")
		return
	}
}

////////////////////////////
const oktaPollCheckPath = "/api/v0/oktaPollCheck"

func (state *RuntimeState) oktaPollCheckHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if !(r.Method == "POST" || r.Method == "GET") {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	authUser, currentAuthLevel, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)

	// TODO: check if okta 2fa is enabled

	oktaAuth, ok := state.passwordChecker.(*okta.PasswordAuthenticator)
	if !ok {
		logger.Println("password authenticator is not okta")
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Apperent Misconfiguration")
		return
	}
	pushResponse, err := oktaAuth.ValidateUserPush(authUser)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating OKTA push")
		return
	}
	switch pushResponse {
	case okta.PushResponseApproved:
		// TODO: add notification
		_, err = state.updateAuthCookieAuthlevel(w, r, currentAuthLevel|AuthTypeOkta2FA)
		if err != nil {
			logger.Printf("Auth Cookie NOT found ? %s", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating VIP token")
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	case okta.PushResponseWaiting:
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "Push already sent")
		return
	case okta.PushResponseRejected:
		state.writeFailureResponse(w, r, http.StatusForbidden, "Failure when validating OKTA push")
		return
	default:
		// TODO better message here!
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "Push already sent")
		return
	}

}