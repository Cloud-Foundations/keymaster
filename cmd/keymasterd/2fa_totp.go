package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image/png"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/pquerna/otp/totp"
)

const labelRSA = "totp:rsa:"
const totpGeneratNewPath = "/totp/GenerateNew/"
const totpValidateNewPath = "/totp/ValidateNew/"

func (state *RuntimeState) encryptWithPublicKeys(clearTextMessage []byte) ([][]byte, error) {
	var cipherTexts [][]byte
	for _, key := range state.KeymasterPublicKeys {
		logger.Debugf(3, "encryptWithPublicKeys: On internal loop with type %T", key)
		// TODO: do Handle ECC keys
		rsaPubKey, ok := key.(*rsa.PublicKey)
		if ok {
			label := []byte(labelRSA)
			rng := rand.Reader
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, rsaPubKey, clearTextMessage, label)
			if err != nil {
				logger.Printf("Error from encryption: %s\n", err)
				return nil, err
			}
			cipherTexts = append(cipherTexts, ciphertext)
			continue
		}
	}
	if len(cipherTexts) < 1 {
		return nil, errors.New("cannot encrypt with any key")
	}
	return cipherTexts, nil
}

func (state *RuntimeState) decryptWithPublicKeys(cipherTexts [][]byte) ([]byte, error) {
	logger.Debugf(5, "signer type=%T", state.Signer)
	for _, cipherText := range cipherTexts {
		rsaPrivateKey, ok := state.Signer.(*rsa.PrivateKey)
		if ok {
			label := []byte(labelRSA)
			rng := rand.Reader
			plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, rsaPrivateKey, cipherText, label)
			if err != nil {
				logger.Printf("Error from decryption: %s\n", err)
				continue
			}
			return plaintext, nil
		}

	}
	return nil, errors.New("Cannot decrypt Message")
}

func (state *RuntimeState) GenerateNewTOTP(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	// TODO: think if we are going to allow admins to register these tokens
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	// TODO: check if TOTP is even enabled.

	// TODO: check for method, we should only allow POST requests

	profile, _, fromCache, err := state.LoadUserProfile(authData.Username)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		state.writeFailureResponse(w, r, http.StatusServiceUnavailable, "DB in cached state, cannot create new TOTP now")
		return
	}
	logger.Debugf(2, "%v", profile)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      state.HostIdentity,
		AccountName: authData.Username,
	})
	if err != nil {
		logger.Printf("generating new key error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	encryptedKeys, err := state.encryptWithPublicKeys([]byte(key.Secret()))
	if err != nil {
		logger.Printf("Encrypting key error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	profile.PendingTOTPSecret = &encryptedKeys
	err = state.SaveUserProfile(authData.Username, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	logger.Debugf(3, "Generate TOTP: profile=%+v", profile)
	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)
	base64Image := base64.StdEncoding.EncodeToString(buf.Bytes())
	logger.Debugf(10, "base64image=%s", base64Image)
	// We need custom CSP policy to allow embedded images
	w.Header().Set("Content-Security-Policy", "default-src 'self' ;img-src 'self'  data: ;style-src 'self' fonts.googleapis.com 'unsafe-inline'; font-src fonts.gstatic.com fonts.googleapis.com")
	displayData := newTOTPPageTemplateData{
		AuthUsername:    authData.Username,
		Title:           "New TOTP Generation", //TODO: maybe include username?
		TOTPSecret:      key.Secret(),
		TOTPBase64Image: template.HTML("<img src=\"data:image/png;base64," + base64Image + "\" alt=\"beastie.png\" scale=\"0\" />"),
	}
	returnAcceptType := getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		err = state.htmlTemplate.ExecuteTemplate(w, "newTOTPage", displayData)
		if err != nil {
			logger.Printf("Failed to execute %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	default:
		json.NewEncoder(w).Encode(displayData)
	}
	return
}

func (state *RuntimeState) validateNewTOTP(w http.ResponseWriter, r *http.Request) {
	authUser, _, otpValue, err := state.commonTOTPPostHandler(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Printf("Error in common Handler")
		return
	}
	OTPString := fmt.Sprintf("%06d", otpValue)
	profile, _, fromCache, err := state.LoadUserProfile(authUser)
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
	if profile.PendingTOTPSecret == nil {
		logger.Printf("No pending Secrets")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "No pending Secrets")
		return
	}
	// TODO: The encrypted value MUST have also an expiration
	encryptedKeys := profile.PendingTOTPSecret
	clearTextKey, err := state.decryptWithPublicKeys(*encryptedKeys)
	if err != nil {
		logger.Printf("Decrypting secret error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	valid := totp.Validate(OTPString, string(clearTextKey))
	if !valid {
		//render try again vailidate page, with an error message
		logger.Printf("Invalid Entry")
		w.WriteHeader(http.StatusBadRequest)
		displayData := newTOTPPageTemplateData{
			AuthUsername: authUser,
			Title:        "Validate New TOTP Generation", //TODO: maybe include username?
			ErrorMessage: "Invalid TOTP value, please try again",
		}
		returnAcceptType := getPreferredAcceptType(r)
		switch returnAcceptType {
		case "text/html":
			err = state.htmlTemplate.ExecuteTemplate(w, "newTOTPage", displayData)
			if err != nil {
				logger.Printf("Failed to execute %v", err)
				//http.Error(w, "error", http.StatusInternalServerError)
				return
			}
		default:
			json.NewEncoder(w).Encode(displayData)
		}
		return

	}
	// TODO: check if same secret already there
	newTOTPAuthData := totpAuthData{
		CreatedAt:       time.Now(),
		EncryptedSecret: *profile.PendingTOTPSecret,
		ValidatorAddr:   r.RemoteAddr,
		Enabled:         true,
	}
	newIndex := newTOTPAuthData.CreatedAt.Unix()
	profile.TOTPAuthData[newIndex] = &newTOTPAuthData
	profile.PendingTOTPSecret = nil
	profile.UserHasRegistered2ndFactor = true
	err = state.SaveUserProfile(authUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	//redirect to profile page?
	http.Redirect(w, r, profilePath, 302)
}

const totpTokenManagementPath = "/api/v0/manageTOTPToken"

func (state *RuntimeState) totpTokenManagerHandler(w http.ResponseWriter,
	r *http.Request) {
	// User must be logged in
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	// TODO(camilo_viecco1): reorder checks so that simple checks are done
	// before checking user creds
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	// TODO: ensure is a valid method (POST)
	if r.Method != "POST" {
		logger.Printf("Wanted Post got='%s'", r.Method)
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	err = r.ParseForm()
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Error parsing form")
		return
	}
	logger.Debugf(3, "Form: %+v", r.Form)

	assumedUser := r.Form.Get("username")

	// Have admin rights = Must be admin + authenticated with U2F
	hasAdminRights := state.IsAdminUserAndU2F(authData.Username,
		authData.AuthType)

	// Check params
	if !hasAdminRights && assumedUser != authData.Username {
		logger.Printf("bad username authUser=%s requested=%s",
			authData.Username, r.Form.Get("username"))
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}

	tokenIndex, err := strconv.ParseInt(r.Form.Get("index"), 10, 64)
	if err != nil {
		logger.Printf("tokenindex is not a number")
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"tokenindex is not a number")
		return
	}

	//Do a redirect
	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes",
			http.StatusServiceUnavailable)
		return
	}

	// Todo: check for negative values
	_, ok := profile.TOTPAuthData[tokenIndex]
	if !ok {
		logger.Printf("bad index number")
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"bad index Value")
		return
	}
	actionName := r.Form.Get("action")
	switch actionName {
	case "Update":
		tokenName := r.Form.Get("name")
		if m, _ := regexp.MatchString("^[-/.a-zA-Z0-9_ ]+$", tokenName); !m {
			logger.Printf("%s", tokenName)
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"invalidtokenName")
			return
		}
		profile.TOTPAuthData[tokenIndex].Name = tokenName
	case "Disable":
		profile.TOTPAuthData[tokenIndex].Enabled = false
	case "Enable":
		profile.TOTPAuthData[tokenIndex].Enabled = true
	case "Delete":
		delete(profile.TOTPAuthData, tokenIndex)
	default:
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Invalid Operation")
		return
	}
	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	// Success!
	returnAcceptType := getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		http.Redirect(w, r, profileURI(authData.Username, assumedUser), 302)
	default:
		w.WriteHeader(200)
		fmt.Fprintf(w, "Success!")
	}
	return
}

// TODO: these consts need to be eventually turned into config settings
const minSecsBetweenTOTPValidations = 2
const numHoursForLocalTOTPRateLimitReset = 24
const numFailedTOTPChecksForTimeoutIncrease = 5

// This function is the one actually validating the TOTP values, returns err non nil
// if there is a problem with the internal state. Returns true if the previous OTP success
// for this user is NOT on this period AND one of the otp values matches the one of the user's
// registered keys.
func (state *RuntimeState) validateUserTOTP(username string, OTPValue int, t time.Time) (bool, error) {
	//Do a redirect
	profile, _, fromCache, err := state.LoadUserProfile(username)
	if err != nil {
		logger.Printf("validateUserTOTP: loading profile error: %v", err)
		return false, err
	}

	state.totpLocalTateLimitMutex.Lock()
	userRateLimit := state.totpLocalRateLimit[username]
	if userRateLimit.lastCheckTime.
		Add(time.Second * time.Duration(minSecsBetweenTOTPValidations)).
		After(time.Now()) {
		state.totpLocalTateLimitMutex.Unlock()
		return false, err
	}
	userRateLimit.lastCheckTime = time.Now()
	state.totpLocalRateLimit[username] = userRateLimit
	state.totpLocalTateLimitMutex.Unlock()

	if userRateLimit.lockoutExpirationTime.After(time.Now()) {
		return false, err
	}
	if userRateLimit.lastFailTime.
		Add(time.Duration(numHoursForLocalTOTPRateLimitReset) * time.Hour).Before(time.Now()) {
		userRateLimit.failCount = 0
		userRateLimit.lockoutExpirationTime = time.Now()
	}

	if fromCache {
		//TODO we what do do on disconnected? I think we should allow it to proceed, but
		// enable a blacklist so that ip addresses/users have a limit of say 5/min?
		logger.Printf("DB is being cached and requesting registration aborting it")
		//http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
		//return
	}
	//Check if value is on blacklist for that user?
	// Check if there is a value successfully accepted for that counter value
	const defaultPeriod = 30
	counter := int64(math.Floor(float64(t.Unix()) / float64(defaultPeriod)))
	if profile.LastSuccessfullTOTPCounter == counter {
		logger.Printf("validateUserTOTP: already done TOTP within time period")
		return false, nil
	}
	OTPString := fmt.Sprintf("%06d", OTPValue)
	//Now iterate
	for _, deviceInfo := range profile.TOTPAuthData {
		if !deviceInfo.Enabled {
			continue
		}
		clearTextKey, err := state.decryptWithPublicKeys(deviceInfo.EncryptedSecret)
		if err != nil {
			logger.Printf("Decrypting secret error: %v", err)
			return false, err
		}

		valid := totp.Validate(OTPString, string(clearTextKey))
		if !valid {
			continue
		}
		if !fromCache {
			profile.LastSuccessfullTOTPCounter = counter
			err = state.SaveUserProfile(username, profile)
			if err != nil {
				logger.Printf("Saving profile error: %v", err)
				return false, err
			}
		}
		userRateLimit.failCount = 0
		userRateLimit.lockoutExpirationTime = time.Now()
		state.totpLocalTateLimitMutex.Lock()
		state.totpLocalRateLimit[username] = userRateLimit
		state.totpLocalTateLimitMutex.Unlock()
		return true, nil
	}
	userRateLimit.failCount++
	//every 5th bad try, make it wait an extra hour
	if userRateLimit.failCount%numFailedTOTPChecksForTimeoutIncrease == 0 {
		userRateLimit.lockoutExpirationTime.Add(time.Duration(3600) * time.Second)
	}
	userRateLimit.lastFailTime = time.Now()
	state.totpLocalTateLimitMutex.Lock()
	state.totpLocalRateLimit[username] = userRateLimit
	state.totpLocalTateLimitMutex.Unlock()

	return false, nil
}

func (state *RuntimeState) commonTOTPPostHandler(w http.ResponseWriter, r *http.Request, requiredAuthLevel int) (string, int, int, error) {
	// User must be logged in
	if state.sendFailureToClientIfLocked(w, r) {
		return "", 0, 0, errors.New("server still sealed")
	}
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, requiredAuthLevel)
	if err != nil {
		logger.Debugf(1, "%v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return "", 0, 0, err
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	// TODO: ensure is a valid method (POST)
	if r.Method != "POST" {
		logger.Printf("Wanted Post got='%s'", r.Method)
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return "", 0, 0, errors.New("Invalid Method requeted")
	}
	err = r.ParseForm()
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		return "", 0, 0, err
	}
	logger.Debugf(3, "Form: %+v", r.Form)
	var OTPString string
	if val, ok := r.Form["OTP"]; ok {
		if len(val) > 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Just one OTP Value allowed")
			logger.Printf("Login with multiple OTP Values")
			return "", 0, 0, errors.New("multiple OTP values")
		}
		OTPString = val[0]
	}
	otpValue, err := strconv.Atoi(OTPString)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing OTP value")
		return "", 0, 0, err
	}

	return authData.Username, authData.AuthType, otpValue, nil
}

const totpVerifyHandlerPath = "/api/v0/VerifyTOTP"

func (state *RuntimeState) verifyTOTPHandler(w http.ResponseWriter, r *http.Request) {
	authUser, _, otpValue, err := state.commonTOTPPostHandler(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Printf("Error in common Handler")
		return
	}
	valid, err := state.validateUserTOTP(authUser, otpValue, time.Now())
	if err != nil {
		logger.Printf("Error validating UserTOTP. Err: %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	// TODO change these for real continuation Messages.
	if !valid {
		//Send to contine Page of Error?
		state.writeFailureResponse(w, r, http.StatusOK, "Verification Failed")
		return

	}
	http.Redirect(w, r, profilePath, 302)
}

const totpAuthPath = "/api/v0/TOTPAuth"

func (state *RuntimeState) TOTPAuthHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf(1, "Top of TOTPAuthHandler")
	authUser, currentAuthLevel, otpValue, err := state.commonTOTPPostHandler(w, r, AuthTypeAny)
	if err != nil {
		logger.Printf("Error in common Handler err:%s", err)
		return
	}
	logger.Debugf(1, "TOTPAuthHandler, After commonPostHandler, currentAuthLevel=%x", currentAuthLevel)
	state.internalTOTPAuthHandler(w, r, authUser, currentAuthLevel, otpValue)
	return
}
func (state *RuntimeState) internalTOTPAuthHandler(w http.ResponseWriter, r *http.Request, authUser string, currentAuthLevel int, otpValue int) {
	valid, err := state.validateUserTOTP(authUser, otpValue, time.Now())
	if err != nil {
		logger.Printf("Error validating TOTP %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating OTP token")
		return
	}
	if !valid {
		logger.Printf("Invalid OTP value login for %s", authUser)
		// TODO if client is html then do a redirect back to vipLoginPage
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}

	_, err = state.updateAuthCookieAuthlevel(w, r, currentAuthLevel|AuthTypeTOTP)
	if err != nil {
		logger.Printf("Auth Cookie NOT found ? %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating OTP token")
		return
	}
	returnAcceptType := getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		loginDestination := getLoginDestination(r)
		http.Redirect(w, r, loginDestination, 302)
	default:
		loginResponse := proto.LoginResponse{Message: "success"}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)
	}
	return

}
