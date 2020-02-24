package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/authenticators/okta"
	"github.com/Symantec/Dominator/lib/log/testlogger"
)

var oktaTestAuthnURL string

func oktaTestWriteStatus(w http.ResponseWriter, status string) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "    ") // Make life easier for debugging.
	response := okta.OktaApiPrimaryResponseType{Status: status}
	if err := encoder.Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func oktaTestAuthnHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("top of oktaTestAuthnHandler")
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var loginData okta.OktaApiLoginDataType
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&loginData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if loginData.Username != "a-user" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch loginData.Password {
	case "good-password":
		oktaTestWriteStatus(w, "SUCCESS")
		return
	case "needs-2FA":
		response := okta.OktaApiPrimaryResponseType{
			StateToken:      "valid-otp",
			ExpiresAtString: "2035-11-03T10:15:57.000Z",
			Status:          "MFA_REQUIRED",
			Embedded: okta.OktaApiEmbeddedDataResponseType{
				Factor: []okta.OktaApiMFAFactorsType{
					okta.OktaApiMFAFactorsType{
						Id:         "someid",
						FactorType: "token:software:totp",
						VendorName: "OKTA"},
					okta.OktaApiMFAFactorsType{
						Id:         "anotherid",
						FactorType: "push",
						VendorName: "OKTA",
					},
				}},
		}
		encoder := json.NewEncoder(w)
		if err := encoder.Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case "needs-2FA-waiting":
		response := okta.OktaApiPrimaryResponseType{
			StateToken:      "push-send-waiting",
			ExpiresAtString: "2035-11-03T10:15:57.000Z",
			Status:          "MFA_REQUIRED",
			Embedded: okta.OktaApiEmbeddedDataResponseType{
				Factor: []okta.OktaApiMFAFactorsType{
					okta.OktaApiMFAFactorsType{
						Id:         "anotherid",
						FactorType: "push",
						VendorName: "OKTA",
					},
				}},
		}
		encoder := json.NewEncoder(w)
		if err := encoder.Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	default:
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func oktaTestFactorAuthnHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("top of  oktaTestFactorAuthnHandler")
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// For now we do TOTP only verifyTOTPFactorDataType
	var otpData okta.OktaApiVerifyTOTPFactorDataType
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&otpData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch otpData.StateToken {
	case "valid-otp":
		oktaTestWriteStatus(w, "SUCCESS")
		return
	case "push-send-waiting":
		response := okta.OktaApiPushResponseType{
			Status:       "MFA_CHALLENGE",
			FactorResult: "WAITING",
		}
		encoder := json.NewEncoder(w)

		if err := encoder.Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case "push-send-accept":
		oktaTestWriteStatus(w, "SUCCESS")
		return
	default:
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

}

func setupTestOtkaServer() {
	if oktaTestAuthnURL != "" {
		return
	}
	if listener, err := net.Listen("tcp", "127.0.0.1:"); err != nil {
		panic(err)
	} else {
		addr := listener.Addr().String()
		oktaTestAuthnURL = "http://" + addr + "/api/v1/authn"
		serveMux := http.NewServeMux()
		serveMux.HandleFunc("/api/v1/authn", oktaTestAuthnHandler)
		serveMux.HandleFunc("/api/v1/authn/factors/", oktaTestFactorAuthnHandler)
		go http.Serve(listener, serveMux)
		for {
			if conn, err := net.Dial("tcp", addr); err == nil {
				conn.Close()
				break
			}
			time.Sleep(time.Millisecond * 10)
		}
		return
	}
}

func TestOkta2FAuthHandlerSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	setupTestOtkaServer()
	pa, err := okta.NewPublicTesting(oktaTestAuthnURL, testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	state.passwordChecker = pa
	ok, err := pa.PasswordAuthenticate("a-user", []byte("needs-2FA"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("should have authenticated")
	}
	//Now we can acutally all the otp call
	// End of Setup
	cookieVal, err := state.setNewAuthCookie(nil, "a-user", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	otpValue := "123456" //does not matter
	data := url.Values{}
	data.Set("OTP", otpValue)
	t.Logf("i testverify url_Data='%+v'", data)
	verifyReq, err := http.NewRequest("POST", okta2FAauthPath, bytes.NewBufferString(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	verifyReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(verifyReq, state.Okta2FAuthHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	//now we verifyPoll Success
	verifyPushReq, err := http.NewRequest("POST", oktaPollCheckPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifyPushReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(verifyPushReq, state.oktaPollCheckHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

func TestOkta2FAPushStartAndWait(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	setupTestOtkaServer()
	pa, err := okta.NewPublicTesting(oktaTestAuthnURL, testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	state.passwordChecker = pa
	ok, err := pa.PasswordAuthenticate("a-user", []byte("needs-2FA-waiting"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("should have authenticated")
	}
	//Now we can acutally all the otp call
	// End of Setup
	cookieVal, err := state.setNewAuthCookie(nil, "a-user", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	//now we verifyPoll Success
	startPushReq, err := http.NewRequest("POST", oktaPushStartPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	startPushReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(startPushReq, state.oktaPushStartHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

	pushWaitReq, err := http.NewRequest("POST", oktaPollCheckPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	pushWaitReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(pushWaitReq, state.oktaPollCheckHandler, http.StatusPreconditionFailed)
	if err != nil {
		t.Fatal(err)
	}
}
