package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/authenticators/okta"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

const okta2FAauthPath = "/api/v0/okta2FAAuth"
const oktaPushStartPath = "/api/v0/oktaPushStart"
const oktaPollCheckPath = "/api/v0/oktaPollCheck"

func (state *RuntimeState) Okta2FAuthHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf(3, "Top of Okta2FAuthHandler")
	authUser, currentAuthLevel, otpValue, err := state.commonTOTPPostHandler(w, r, AuthTypeAny)
	if err != nil {
		//Common handler handles returning the right error response to caller
		logger.Printf("Error in common Handler")
		return
	}
	oktaAuth, ok := state.passwordChecker.(*okta.PasswordAuthenticator)
	if !ok {
		logger.Println("password authenticator is not okta")
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Apparent Misconfiguration")
		return
	}
	start := time.Now()
	valid, err := oktaAuth.ValidateUserOTP(authUser, otpValue)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating Okta MFA token")
		return
	}
	metricLogExternalServiceDuration("okta-otp", time.Since(start))
	metricLogAuthOperation(getClientType(r), proto.AuthTypeOkta2FA, valid)
	if !valid {
		logger.Printf("Invalid OTP value login for %s", authUser)
		// TODO if client is html then do a redirect back to 2FALoginPage
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return

	}
	// OTP check was  successful
	logger.Debugf(1, "Successful Okta OTP auth for user: %s", authUser)

	// TODO ADD okta events to eventmond
	//eventNotifier.PublishVIPAuthEvent(eventmon.VIPAuthTypeOTP, authUser)

	_, err = state.updateAuthCookieAuthlevel(w, r, currentAuthLevel|AuthTypeOkta2FA)
	if err != nil {
		logger.Printf("Auth Cookie NOT found ? %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating Okta MFA token")
		return
	}
	// Now we send to the appropriate place
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
	}
	return
}

func (state *RuntimeState) oktaPushStartHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf(3, "top of oktaPushStartHandler")
	if state.sendFailureToClientIfLocked(w, r) {
		logger.Printf("Invalid state on oktaPushStartHandler (not unsealed)")
		return
	}
	logger.Printf("oktaPushStartHandler post lock")
	if r.Method != "POST" && r.Method != "GET" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	oktaAuth, ok := state.passwordChecker.(*okta.PasswordAuthenticator)
	if !ok {
		logger.Debugf(2, "oktaPushStartHandler: password authenticator is not okta is of type %T", oktaAuth)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Apperent Misconfiguration")
		return
	}
	userResponse, err := oktaAuth.GetValidUserResponse(authData.Username)
	if err != nil {
		logger.Debugf(2, "oktaPushStartHandler: ")
	}
	if len(userResponse.Embedded.Factor) < 1 {
		logger.Printf("oktaPushStartHandler: user %s does not have valid authenticators", authData.Username)
		logger.Debugf(2, "oktaPushStartHandler: userdata for broken user%s is :%s", authData.Username, userResponse)
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "No valid MFA authenticators available")
		return
	}

	pushResponse, err := oktaAuth.ValidateUserPush(authData.Username)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating OKTA push")
		return
	}
	logger.Debugf(2, "oktaPushStartHandler: after validating push response=%+v", pushResponse)
	switch pushResponse {
	case okta.PushResponseWaiting:
		w.WriteHeader(http.StatusOK)
		return
	default:
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "Push already sent")
		return
	}
}

func (state *RuntimeState) oktaPollCheckHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf(3, "top of oktaPollCheckHandler")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if r.Method != "POST" && r.Method != "GET" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	oktaAuth, ok := state.passwordChecker.(*okta.PasswordAuthenticator)
	if !ok {
		logger.Println("password authenticator is not okta")
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Apperent Misconfiguration")
		return
	}
	pushResponse, err := oktaAuth.ValidateUserPush(authData.Username)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating OKTA push")
		return
	}
	switch pushResponse {
	case okta.PushResponseApproved:
		// TODO: add notification on eventmond
		metricLogAuthOperation(getClientType(r), proto.AuthTypeOkta2FA, true)
		_, err = state.updateAuthCookieAuthlevel(w, r,
			authData.AuthType|AuthTypeOkta2FA)
		if err != nil {
			logger.Printf("Auth Cookie NOT found ? %s", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating Okta token")
			return
		}
		logger.Debugf(2, "oktaPollCheckHandler success")
		w.WriteHeader(http.StatusOK)
		return
	case okta.PushResponseWaiting:
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "Push already sent")
		return
	case okta.PushResponseRejected:
		metricLogAuthOperation(getClientType(r), proto.AuthTypeOkta2FA, false)
		state.writeFailureResponse(w, r, http.StatusForbidden, "Failure when validating OKTA push")
		return
	default:
		// TODO better message here!
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "Push already sent")
		return
	}
}
