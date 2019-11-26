package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/pquerna/otp/totp"
)

func TestEncryptDecryptSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	testSecret := "superSecret"
	cipherTexts, err := state.encryptWithPublicKeys([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	plainTextBytes, err := state.decryptWithPublicKeys(cipherTexts)

	if err != nil {
		t.Fatal(err)
	}
	if string(plainTextBytes) != testSecret {
		t.Fatal("values do not match")
	}
}

func TestGenerateNewTOTPSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypeU2F)

	state.signerPublicKeyToKeymasterKeys()

	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	err = initDB(state)
	if err != nil {
		t.Fatal(err)
	}
	state.HostIdentity = "testHost"

	// End of setup

	req, err := http.NewRequest("GET", totpGeneratNewPath, nil)
	if err != nil {
		t.Fatal(err)
		//return nil, err
	}
	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)

	tokenRR, err := checkRequestHandlerCode(req, state.GenerateNewTOTP, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	resultAccessToken := newTOTPPageTemplateData{}
	body := tokenRR.Result().Body
	err = json.NewDecoder(body).Decode(&resultAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("totpDataToken='%+v'", resultAccessToken)

	// now we validate
	otpValue, err := totp.GenerateCode(resultAccessToken.TOTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data := url.Values{}
	data.Set("OTP", otpValue)
	t.Logf("url_Data='%+v'", data)
	validateReq, err := http.NewRequest("POST", totpValidateNewPath, bytes.NewBufferString(data.Encode()))
	if err != nil {
		t.Fatal(err)
		//return nil, err
	}
	validateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	validateReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(validateReq, state.validateNewTOTP, http.StatusFound)
	if err != nil {
		t.Fatal(err)
	}
	//now check auth against it
	now := time.Now()
	otpValueInt, err := strconv.Atoi(otpValue)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := state.validateUserTOTP("username", otpValueInt, now)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("should have been valid")
	}
	// now we retry with same value and should fail
	valid, err = state.validateUserTOTP("username", otpValueInt, now)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("should NOT have been valid")
	}

}

func setupTestStateWithTOTPSecret(t *testing.T, state *RuntimeState, cookieAuth int) (*http.Cookie, string, error) {

	authUser := "username"
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "keymaster-totp", //TODO: get the actual name
		AccountName: authUser,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, _, _, err := state.LoadUserProfile(authUser)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKeys, err := state.encryptWithPublicKeys([]byte(key.Secret()))
	if err != nil {
		t.Fatal(err)
	}
	newTOTPAuthData := totpAuthData{
		CreatedAt:       time.Now(),
		EncryptedSecret: encryptedKeys,
		//ValidatorAddr:   r.RemoteAddr,
		Enabled: true,
	}
	newIndex := newTOTPAuthData.CreatedAt.Unix()
	profile.TOTPAuthData[newIndex] = &newTOTPAuthData

	err = state.SaveUserProfile(authUser, profile)
	if err != nil {
		t.Fatal(err)
	}
	cookieVal, err := state.setNewAuthCookie(nil, "username", cookieAuth)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	return &authCookie, key.Secret(), nil
}

func TestVerifyTOTPHandlerSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypeU2F)

	state.signerPublicKeyToKeymasterKeys()

	dir, err := ioutil.TempDir("", "example-1")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	err = initDB(state)
	if err != nil {
		t.Fatal(err)
	}

	// End of setup
	authCookie, totpSecret, err := setupTestStateWithTOTPSecret(t, state, AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	otpValue, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data := url.Values{}
	data.Set("OTP", otpValue)
	t.Logf("i testverify url_Data='%+v'", data)
	verifyReq, err := http.NewRequest("POST", totpValidateNewPath, bytes.NewBufferString(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	verifyReq.AddCookie(authCookie)
	_, err = checkRequestHandlerCode(verifyReq, state.verifyTOTPHandler, http.StatusFound)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthTOTPHandlerSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypeTOTP)

	state.signerPublicKeyToKeymasterKeys()

	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	err = initDB(state)
	if err != nil {
		t.Fatal(err)
	}
	// End of setup
	authCookie, totpSecret, err := setupTestStateWithTOTPSecret(t, state, AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}

	otpValue, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data := url.Values{}
	data.Set("OTP", otpValue)
	t.Logf("i testverify url_Data='%+v'", data)
	verifyReq, err := http.NewRequest("POST", totpValidateNewPath, bytes.NewBufferString(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	verifyReq.AddCookie(authCookie)
	_, err = checkRequestHandlerCode(verifyReq, state.TOTPAuthHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTOTPTokenManagerHandlerUpdateSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypePassword)

	state.signerPublicKeyToKeymasterKeys()

	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	err = initDB(state)
	if err != nil {
		t.Fatal(err)
	}
	//
	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeAny)
	if err != nil {
		t.Fatal(err)
	}
	//cookieReq.AddCookie(&authCookie)
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}

	const newName = "New./-X"
	const oldName = "Old"

	profile := &userProfile{}
	profile.TOTPAuthData = make(map[int64]*totpAuthData)
	profile.TOTPAuthData[0] = &totpAuthData{Name: oldName}
	err = state.SaveUserProfile("username", profile)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("username", "username")
	form.Add("index", "0")
	form.Add("name", newName)
	form.Add("action", "Update")

	req, err := http.NewRequest("POST", totpTokenManagementPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&authCookie)
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	val, err := checkRequestHandlerCode(req, state.totpTokenManagerHandler, http.StatusOK)
	if err != nil {
		t.Log(val)
		t.Fatal(err)
	}
	// Todo... check against the FS.
	profile, _, _, err = state.LoadUserProfile("username")
	if err != nil {
		t.Fatal(err)
	}
	if profile.TOTPAuthData[0].Name != newName {
		t.Fatal("update not successul")
	}
}
