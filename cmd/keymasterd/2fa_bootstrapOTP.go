package main

import (
	"crypto/sha512"
	"crypto/subtle"
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
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	state.logger.Debugf(3, "Got client POST connection")
	if err := r.ParseForm(); err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"Error parsing form")
		return
	}
	authUser, currentAuthLevel, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		state.logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	var inputOtpHash [sha512.Size]byte
	if val, ok := r.Form["OTP"]; !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"No OTP value provided")
		state.logger.Printf("Bootstrap OTP login without OTP value")
		return
	} else {
		if len(val) > 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Just one OTP value allowed")
			state.logger.Printf("Bootstrap OTP login with multiple OTP values")
			return
		}
		inputOtpHash = sha512.Sum512([]byte(val[0]))
	}
	profile, _, fromCache, err := state.LoadUserProfile(authUser)
	if err != nil {
		state.logger.Printf("error loading user profile err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"Failure loading user profile")
		return
	}
	if fromCache {
		state.writeFailureResponse(w, r, http.StatusServiceUnavailable,
			"Working in DB disconnected mode, try again later")
		return
	}
	requiredOtpHash := state.userBootstrapOtpHash(profile, fromCache)
	if len(requiredOtpHash) < 1 {
		state.writeFailureResponse(w, r, http.StatusPreconditionFailed,
			"No valid Bootstrap OTP hash saved")
		return
	}
	if subtle.ConstantTimeCompare(inputOtpHash[:], requiredOtpHash) != 1 {
		state.logger.Debugf(0, "Invalid Bootstrap OTP value for %s\n",
			authUser)
		var tmp [sha512.Size]byte
		copy(tmp[:], requiredOtpHash)
		state.logger.Debugf(4, "  input: \"%v\" required: \"%v\"\n",
			inputOtpHash, tmp)
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"Invalid Bootstrap OTP")
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

func (state *RuntimeState) trySelfServiceGenerateBootstrapOTP(username string,
	profile *userProfile) {
	if !state.Config.Base.AllowSelfServiceBootstrapOTP ||
		profile.UserHasRegistered2ndFactor ||
		len(state.userBootstrapOtpHash(profile, false)) > 0 ||
		state.emailManager == nil {
		return
	}
	bootstrapOtpValue, err := genRandomString()
	if err != nil {
		state.logger.Printf("error generating Bootstrap OTP: %s", err)
		return
	}
	duration := time.Minute * 5
	bootstrapOtpHash := sha512.Sum512([]byte(bootstrapOtpValue))
	bootstrapOTP := bootstrapOTPData{
		ExpiresAt:  time.Now().Add(duration),
		Sha512Hash: bootstrapOtpHash[:],
	}
	profile.BootstrapOTP = bootstrapOTP
	var fingerprint [4]byte
	copy(fingerprint[:], bootstrapOtpHash[:4])
	err = state.sendBootstrapOtpEmail(bootstrapOtpHash[:],
		bootstrapOtpValue, duration, username, username)
	if err != nil {
		state.logger.Printf("error sending email: %s", err)
		return
	}
	err = state.SaveUserProfile(username, profile)
	if err != nil {
		state.logger.Printf("error saving profile: %s", err)
		return
	}
	state.logger.Debugf(0,
		"generated bootstrap OTP by/for: %s, duration: %s, hash: %x\n",
		duration, username, bootstrapOtpHash)
}

func (state *RuntimeState) userBootstrapOtpHash(profile *userProfile,
	fromCache bool) []byte {
	if len(profile.U2fAuthData) > 0 || len(profile.TOTPAuthData) > 0 {
		return nil
	}
	if fromCache { // Since we will want to clear the OTP, require connection.
		return nil
	}
	if len(profile.BootstrapOTP.Sha512Hash) < 1 {
		return nil
	}
	if time.Since(profile.BootstrapOTP.ExpiresAt) >= 0 {
		return nil
	}
	return profile.BootstrapOTP.Sha512Hash
}
