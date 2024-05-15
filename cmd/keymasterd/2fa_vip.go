package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/Cloud-Foundations/keymaster/proto/eventmon"
)

func (state *RuntimeState) startVIPPush(cookieVal string, username string) error {
	transactionId, err := state.Config.SymantecVIP.Client.StartUserVIPPush(username)
	if err != nil {
		logger.Println(err)
		return err
	}
	newLocalData := pushPollTransaction{Username: username, TransactionID: transactionId, ExpiresAt: time.Now().Add(maxAgeSecondsVIPCookie * time.Second)}
	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	state.vipPushCookie[cookieVal] = newLocalData

	return nil
}

// /
const vipAuthPath = "/api/v0/vipAuth"

func (state *RuntimeState) VIPAuthHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	//Check for valid method here?
	switch r.Method {
	case "GET":
		logger.Debugf(3, "Got client GET connection")
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		logger.Debugf(3, "Got client POST connection")
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	//authUser, authType, err := state.checkAuth(w, r, AuthTypeAny)
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	var OTPString string
	if val, ok := r.Form["OTP"]; ok {
		if len(val) > 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Just one OTP Value allowed")
			logger.Printf("Login with multiple OTP Values")
			return
		}
		OTPString = val[0]
	}
	otpValue, err := strconv.Atoi(OTPString)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing OTP value")
		return
	}
	if !state.Config.SymantecVIP.Enabled {
		logger.Printf("request for VIP auth, but VIP not enabled")
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "VIP not enabled")
		return
	}

	start := time.Now()
	valid, err := state.Config.SymantecVIP.Client.ValidateUserOTP(authData.Username, otpValue)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating VIP token")
		return
	}

	metricLogExternalServiceDuration("vip", time.Since(start))

	//
	metricLogAuthOperation(getClientType(r), proto.AuthTypeSymantecVIP, valid)
	if !valid {
		logger.Printf("Invalid VIP OTP value login for %s", authData.Username)
		// TODO if client is html then do a redirect back to vipLoginPage
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return

	}

	// OTP check was  successful
	logger.Debugf(1, "Successful vipOTP auth for user: %s", authData.Username)
	eventNotifier.PublishVIPAuthEvent(eventmon.VIPAuthTypeOTP, authData.Username)
	_, err = state.updateAuthCookieAuthlevel(w, r,
		authData.AuthType|AuthTypeSymantecVIP)
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
		eventNotifier.PublishWebLoginEvent(authData.Username)
		http.Redirect(w, r, loginDestination, 302)
	default:
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)
		//fmt.Fprintf(w, "Success!")
	}
	return
}

func (state *RuntimeState) getPushPollTransaction(cookieValue string) (pushPollTransaction, bool) {
	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	value, ok := state.vipPushCookie[cookieValue]
	return value, ok
}

// /////////////////////////
const vipPushStartPath = "/api/v0/vipPushStart"

func (state *RuntimeState) vipPushStartHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if !state.Config.SymantecVIP.Enabled {
		logger.Printf("asked for push status but VIP is not enabled")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "")
		return
	}
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	logger.Debugf(0, "Vip push start authuser=%s", authData.Username)
	vipPushCookie, err := r.Cookie(vipTransactionCookieName)
	if err != nil {
		logger.Printf("%v", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Missing Cookie")
		return
	}
	pushTransaction, ok := state.getPushPollTransaction(vipPushCookie.Value)
	if ok {
		err := errors.New("push transaction found will not start another one")
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Push already sent")
		return
	}
	if len(pushTransaction.TransactionID) > 0 {
		err := errors.New("VIP push transaction already initiated")
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "Push already sent")
		return
	}
	err = state.startVIPPush(vipPushCookie.Value, authData.Username)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Cookie not setup ")
		return
	}

	w.WriteHeader(http.StatusOK)
	return
}

// //////////////////////////
const vipPollCheckPath = "/api/v0/vipPollCheck"

func (state *RuntimeState) VIPPollCheckHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if !state.Config.SymantecVIP.Enabled {
		logger.Printf("asked for push status but VIP is not enabled")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "")
		return
	}

	//Check for valid method here?
	switch r.Method {
	case "GET":
		logger.Debugf(3, "Got client GET connection")
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		logger.Debugf(3, "Got client POST connection")
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	logger.Debugf(1, "VIPPollCheckHandler: authuser=%s", authData.Username)
	vipPollCookie, err := r.Cookie(vipTransactionCookieName)
	if err != nil {
		logger.Printf("VIPPollCheckHandler: error getting poll cookie %v", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Missing Cookie")
		return
	}
	pushTransaction, ok := state.getPushPollTransaction(vipPollCookie.Value)
	if !ok {
		err := errors.New("VIPPollCheckHandler: push transaction not found for user")
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "Error parsing form")
		return
	}
	//TODO: check username
	valid, err := state.Config.SymantecVIP.Client.VipPushHasBeenApproved(pushTransaction.TransactionID)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error checking push transaction")
		return
	}
	if !valid {
		err := errors.New("Not yet") // usually it is not valid, no need to spam the log
		logger.Debugf(1, "%s", err)
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed, "VIP Push Poller unsuccessful")
		return
	}

	// VIP Push check was  successful
	_, err = state.updateAuthCookieAuthlevel(w, r,
		authData.AuthType|AuthTypeSymantecVIP)
	if err != nil {
		logger.Printf("VIPPollCheckHandler:  Failure to update AuthCookie %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating VIP token")
		return
	}
	eventNotifier.PublishVIPAuthEvent(eventmon.VIPAuthTypePush,
		authData.Username)

	// TODO make something more fancy: JSON?
	w.WriteHeader(http.StatusOK)
	return

}
