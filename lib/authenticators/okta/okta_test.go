package okta

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Symantec/Dominator/lib/log/testlogger"
	"github.com/Symantec/keymaster/lib/simplestorage/memstore"
)

var authnURL string

func authnHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var loginData LoginDataType
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
		writeStatus(w, "SUCCESS")
		return
	case "needs-2FA":
		writeStatus(w, "MFA_REQUIRED")
		return
	case "password-expired":
		writeStatus(w, "PASSWORD_EXPIRED")
		return
	default:
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

// From: https://developer.okta.com/docs/reference/api/authn/#verify-totp-factor
const invalidOTPStringFromDoc = `{
  "errorCode": "E0000068",
  "errorSummary": "Invalid Passcode/Answer",
  "errorLink": "E0000068",
  "errorId": "oaei_IfXcpnTHit_YEKGInpFw",
  "errorCauses": [
    {
      "errorSummary": "Your passcode doesn't match our records. Please try again."
    }
  ]
}`

func factorAuthnHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// For now we do TOTP only verifyTOTPFactorDataType
	var otpData VerifyTOTPFactorDataType
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&otpData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch otpData.StateToken {
	case "valid-otp":
		writeStatus(w, "SUCCESS")
		return
	case "invalid-otp":
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(invalidOTPStringFromDoc))
		return
	case "push-send-waiting":
		response := PushResponseType{
			Status:       "MFA_CHALLENGE",
			FactorResult: "WAITING",
		}
		encoder := json.NewEncoder(w)

		if err := encoder.Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case "push-send-accept":
		writeStatus(w, "SUCCESS")
		return
	case "push-send-timeout":
		response := PushResponseType{
			Status:       "MFA_CHALLENGE",
			FactorResult: "TIMEOUT",
		}
		encoder := json.NewEncoder(w)

		if err := encoder.Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case "push-send-invalidWrapper":
		writeStatus(w, "INVALID")
		return

	default:
		w.WriteHeader(http.StatusUnauthorized)
		return

	}

}

func setupServer() {
	if authnURL != "" {
		return
	}
	if listener, err := net.Listen("tcp", "127.0.0.1:"); err != nil {
		panic(err)
	} else {
		addr := listener.Addr().String()
		authnURL = "http://" + addr + authPath
		serveMux := http.NewServeMux()
		serveMux.HandleFunc(authPath, authnHandler)
		serveMux.HandleFunc(authPath+"/factors/", factorAuthnHandler)
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

func writeStatus(w http.ResponseWriter, status string) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "    ") // Make life easier for debugging.
	response := PrimaryResponseType{Status: status}
	if err := encoder.Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func TestBaseAPI(t *testing.T) {
	setupServer()
	pa, err := NewPublic("somedomain", testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	pa.authnURL = authnURL
	_, err = pa.ValidateUserPush("someuser")
	if err != nil {
		t.Fatal(err)
	}
	memStore := memstore.New()
	err = pa.UpdateStorage(memStore)
	if err != nil {
		t.Fatal(err)
	}
	err = pa.SetAuthnURL("http://localhost.locanet")
	if err != nil {
		t.Fatal(err)
	}
}

func TestNonExistantUser(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{
		authnURL:   authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	ok, err := pa.PasswordAuthenticate("bad-user", []byte("dummy-password"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if ok {
		t.Fatalf("non-existant user did not fail")
	}
}

func TestBadPassword(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	_, err := pa.ValidateUserPush("someuser")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("bad-password"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if ok {
		t.Fatalf("bad password did not fail")
	}
}

func TestGoodPassword(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("good-password"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if !ok {
		t.Fatalf("good password failed")
	}
}

func TestMfaRequired(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("needs-2FA"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if !ok {
		t.Fatalf("good password needing 2FA failed")
	}
}

func TestUserLockedOut(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("password-expired"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if ok {
		t.Fatalf("expired password suceeded")
	}
}

func TestMfaOtpNonExisting(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	valid, err := pa.ValidateUserOTP("someuser", 123456)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("should not have succeeded with no data")
	}
}

func TestMfaOtpExpired(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	expiredUserCachedData := authCacheData{Expires: time.Now().Add(-3 * time.Second)}
	expiredUser := "expiredUser"
	pa.recentAuth[expiredUser] = expiredUserCachedData
	valid, err := pa.ValidateUserOTP(expiredUser, 123456)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("should not have succeeded with expired user")
	}
}

func TestMfaOTPFailNoValidDevices(t *testing.T) {
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	response := PrimaryResponseType{
		StateToken: "foo", Status: "MFA_REQUIRED",
		Embedded: EmbeddedDataResponseType{Factor: []MFAFactorsType{
			MFAFactorsType{Id: "someid", FactorType: "token:software:totp"},
			MFAFactorsType{Id: "someid", VendorName: "OKTA"},
		}},
	}
	expiredUserCachedData := authCacheData{Expires: time.Now().Add(60 * time.Second),
		Response: response,
	}
	noOTPCredsUser := "noOTPCredsUser"
	pa.recentAuth[noOTPCredsUser] = expiredUserCachedData
	valid, err := pa.ValidateUserOTP(noOTPCredsUser, 123456)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("should not have succeeded with no valid mfa")
	}
	//lets also test push at that same time
	pushResponse, err := pa.ValidateUserPush(noOTPCredsUser)
	if err != nil {
		t.Fatal(err)
	}
	if pushResponse != PushResponseRejected {
		t.Fatal("should not have succeeded with user with no mfa user")
	}
}

func TestMFAOTPFailInvalidOTP(t *testing.T) {
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	response := PrimaryResponseType{
		StateToken: "invalid-otp",
		Status:     "MFA_REQUIRED",
		Embedded: EmbeddedDataResponseType{
			Factor: []MFAFactorsType{
				MFAFactorsType{
					Id:         "someid",
					FactorType: "token:software:totp",
					VendorName: "OKTA"},
			}},
	}
	userCachedData := authCacheData{Expires: time.Now().Add(60 * time.Second),
		Response: response,
	}
	goodOTPUser := "goodOTPUser"
	pa.recentAuth[goodOTPUser] = userCachedData
	valid, err := pa.ValidateUserOTP(goodOTPUser, 123456)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("should NOT have succeeded with invalid-otp")
	}

}

func TestMfaOTPSuccess(t *testing.T) {
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	response := PrimaryResponseType{
		StateToken: "valid-otp",
		Status:     "MFA_REQUIRED",
		Embedded: EmbeddedDataResponseType{
			Factor: []MFAFactorsType{
				MFAFactorsType{
					Id:         "someid",
					FactorType: "token:software:totp",
					VendorName: "OKTA"},
			}},
	}
	expiredUserCachedData := authCacheData{Expires: time.Now().Add(60 * time.Second),
		Response: response,
	}
	goodOTPUser := "goodOTPUser"
	pa.recentAuth[goodOTPUser] = expiredUserCachedData
	valid, err := pa.ValidateUserOTP(goodOTPUser, 123456)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("should have succeeded with good  user")
	}
}

func TestMfaPushNonExisting(t *testing.T) {
	setupServer()

	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	pushResult, err := pa.ValidateUserPush("someuser")
	if err != nil {
		t.Fatal(err)
	}
	if pushResult != PushResponseRejected {
		t.Fatal("should not have succeeded with unknown user")
	}
}

func TestMfaPushExpired(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	expiredUserCachedData := authCacheData{Expires: time.Now().Add(-3 * time.Second)}
	expiredUser := "expiredUser"
	pa.recentAuth[expiredUser] = expiredUserCachedData
	pushResult, err := pa.ValidateUserPush(expiredUser)
	if err != nil {
		t.Fatal(err)
	}
	if pushResult != PushResponseRejected {
		t.Fatal("should not have succeeded with unknown user")
	}
}

func TestMfaPushWaiting(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	response := PrimaryResponseType{
		StateToken: "push-send-waiting",
		Status:     "MFA_REQUIRED",
		Embedded: EmbeddedDataResponseType{
			Factor: []MFAFactorsType{
				MFAFactorsType{
					Id:         "someid",
					FactorType: "push",
					VendorName: "OKTA"},
			}},
	}
	needsPushCacheData := authCacheData{
		Expires:  time.Now().Add(60 * time.Second),
		Response: response,
	}
	pushUserWaiting := "puhsUserWaiting"
	pa.recentAuth[pushUserWaiting] = needsPushCacheData
	pushResult, err := pa.ValidateUserPush(pushUserWaiting)
	if err != nil {
		t.Fatal(err)
	}
	if pushResult != PushResponseWaiting {
		t.Fatal("Was supposed to be waiting")
	}
}

func TestMfaPushAccept(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	response := PrimaryResponseType{
		StateToken: "push-send-accept",
		Status:     "MFA_REQUIRED",
		Embedded: EmbeddedDataResponseType{
			Factor: []MFAFactorsType{
				MFAFactorsType{
					Id:         "someid",
					FactorType: "push",
					VendorName: "OKTA"},
			}},
	}
	userCacheData := authCacheData{
		Expires:  time.Now().Add(60 * time.Second),
		Response: response,
	}
	username := "puhsUserAccept"
	pa.recentAuth[username] = userCacheData
	pushResult, err := pa.ValidateUserPush(username)
	if err != nil {
		t.Fatal(err)
	}
	if pushResult != PushResponseApproved {
		t.Fatal("Was supposed to be approved")
	}
}

func TestMfaPushTimeout(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	response := PrimaryResponseType{
		StateToken: "push-send-timeout",
		Status:     "MFA_REQUIRED",
		Embedded: EmbeddedDataResponseType{
			Factor: []MFAFactorsType{
				MFAFactorsType{
					Id:         "someid",
					FactorType: "push",
					VendorName: "OKTA"},
			}},
	}
	userCacheData := authCacheData{
		Expires:  time.Now().Add(60 * time.Second),
		Response: response,
	}
	username := "puhsUserTimeout"
	pa.recentAuth[username] = userCacheData
	pushResult, err := pa.ValidateUserPush(username)
	if err != nil {
		t.Fatal(err)
	}
	if pushResult != PushResonseTimeout {
		t.Fatal("Was supposed to be timeout")
	}
}

func TestMfaPushInvalidWrapper(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	response := PrimaryResponseType{
		StateToken: "push-send-invalidWrapper",
		Status:     "MFA_REQUIRED",
		Embedded: EmbeddedDataResponseType{
			Factor: []MFAFactorsType{
				MFAFactorsType{
					Id:         "someid",
					FactorType: "push",
					VendorName: "OKTA"},
			}},
	}
	userCacheData := authCacheData{
		Expires:  time.Now().Add(60 * time.Second),
		Response: response,
	}
	username := "puhsUserTimeout"
	pa.recentAuth[username] = userCacheData
	pushResult, err := pa.ValidateUserPush(username)
	if err != nil {
		t.Fatal(err)
	}
	if pushResult != PushResponseRejected {
		t.Fatal("Was supposed to be rejected")
	}
}
