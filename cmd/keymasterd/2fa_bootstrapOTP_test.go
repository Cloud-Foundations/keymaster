package main

import (
	"crypto/sha512"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

const (
	testBootstrapOTP  = "S0MerAnDoMeK3y"
	testBootstrapUser = "bob"
)

var testBootstrapOtpHash = sha512.Sum512([]byte(testBootstrapOTP))

func testCreateRuntimeStateForBootstrapOTP(t *testing.T) (
	*RuntimeState, string, error) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		return nil, "", err
	}
	state.Config.Base.AllowedAuthBackendsForWebUI =
		[]string{proto.AuthTypeBootstrapOTP}
	return state, tmpdir, nil
}

func testCreateRuntimeStateWithBootstrapOTP(t *testing.T,
	expiresIn time.Duration) (*RuntimeState, string, error) {
	state, tmpdir, err := testCreateRuntimeStateForBootstrapOTP(t)
	if err != nil {
		return nil, "", err
	}
	profile := &userProfile{BootstrapOTP: bootstrapOTPData{
		ExpiresAt:  time.Now().Add(expiresIn),
		Sha512Hash: testBootstrapOtpHash[:],
	}}
	if err := state.SaveUserProfile(testBootstrapUser, profile); err != nil {
		os.RemoveAll(tmpdir)
		return nil, "", err
	}
	return state, tmpdir, nil
}

func TestBootstrapOtpAuthNotPost(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateForBootstrapOTP(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("GET", "/", nil)
	state.BootstrapOtpAuthHandler(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
}

func TestBootstrapOtpAuthNoCookie(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBootstrapOTP(t, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", "/", nil)
	state.BootstrapOtpAuthHandler(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
}

func TestBootstrapOtpAuthNoOTP(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateForBootstrapOTP(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", "/", nil)
	req.TLS, err = testMakeConnectionState("testdata/bob.pem",
		"testdata/KeymasterCA.pem")
	state.BootstrapOtpAuthHandler(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
}

func TestBootstrapOtpAuthMissingOTP(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBootstrapOTP(t, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", "/", nil)
	req.TLS, err = testMakeConnectionState("testdata/bob.pem",
		"testdata/KeymasterCA.pem")
	state.BootstrapOtpAuthHandler(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
}

func TestBootstrapOtpAuthExpiredOTP(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBootstrapOTP(t,
		-time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", "/", nil)
	req.TLS, err = testMakeConnectionState("testdata/bob.pem",
		"testdata/KeymasterCA.pem")
	req.Form = make(url.Values)
	req.Form.Add("username", testBootstrapUser)
	req.Form.Add("OTP", testBootstrapOTP)
	state.BootstrapOtpAuthHandler(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
}

func TestBootstrapOtpAuthBadOTP(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBootstrapOTP(t, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", "/", nil)
	req.TLS, err = testMakeConnectionState("testdata/bob.pem",
		"testdata/KeymasterCA.pem")
	req.Form = make(url.Values)
	req.Form.Add("username", testBootstrapUser)
	req.Form.Add("OTP", "not-valid")
	state.BootstrapOtpAuthHandler(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
}

func TestBootstrapOtpAuthGoodOTP(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBootstrapOTP(t, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", "/", nil)
	req.TLS, err = testMakeConnectionState("testdata/bob.pem",
		"testdata/KeymasterCA.pem")
	req.Form = make(url.Values)
	req.Form.Add("username", testBootstrapUser)
	req.Form.Add("OTP", testBootstrapOTP)
	cookieVal, err := state.setNewAuthCookie(nil, testBootstrapUser,
		AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)
	state.BootstrapOtpAuthHandler(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
	profile, _, _, err := state.LoadUserProfile(testBootstrapUser)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.BootstrapOTP.Sha512Hash) > 0 {
		t.Errorf("User profile has lingering Bootstrap OTP hash: %v",
			profile.BootstrapOTP.Sha512Hash)
	}
}
