package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
)

func testCreateRuntimeStateWithBothCAs(t *testing.T) (
	*RuntimeState, string, error) {
	state, tmpdir, err := newTestingState(t)
	if err != nil {
		return nil, "", err
	}
	doCleanup := true
	defer func() {
		if doCleanup {
			os.RemoveAll(tmpdir)
		}
	}()
	state.Config.Base.AdminUsers = []string{"alice"}
	adminCaPemData, err := ioutil.ReadFile("testdata/AdminCA.pem")
	if err != nil {
		return nil, "", err
	}
	state.ClientCAPool = x509.NewCertPool()
	if !state.ClientCAPool.AppendCertsFromPEM(adminCaPemData) {
		return nil, "", errors.New("cannot append Admin CA certificate")
	}
	keymasterCaKeyData, err := ioutil.ReadFile("testdata/KeymasterCA.key")
	if err != nil {
		return nil, "", err
	}
	signer, err := getSignerFromPEMBytes(keymasterCaKeyData)
	if err != nil {
		return nil, "", err
	}
	state.Signer = signer
	caCertDer, err := generateCADer(state, state.Signer)
	if err != nil {
		return nil, "", err
	}
	state.caCertDer = append(state.caCertDer, caCertDer)
	state.selfRoleCaCertDer, err = generateSelfRoleRequestingCADer(state, signer)
	if err != nil {
		return nil, "", err
	}

	state.signerPublicKeyToKeymasterKeys()
	state.totpLocalRateLimit = make(map[string]totpRateLimitInfo)
	if err := initDB(state); err != nil {
		t.Fatal(err)
	}
	doCleanup = false
	return state, tmpdir, nil
}

func testMakeConnectionState(certs ...string) (*tls.ConnectionState, error) {
	var chain []*x509.Certificate
	for _, cert := range certs {
		pemData, err := ioutil.ReadFile(cert)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pemData)
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("no CERTIFICATE found")
		}
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, x509Cert)
	}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{chain}},
		nil
}

func TestAuthNoTLS(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("GET", usersPath, nil)
	errorSent, authData := state.sendFailureToClientIfNonAdmin(w, req)
	if errorSent {
		return
	}
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", recorder.Result().StatusCode)
	}
	if authData.Username != "" {
		t.Errorf("expected no username, got: %s", authData.Username)
	}
	state.dbDone <- struct{}{}
}

func TestAuthCertAdminUser(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("GET", usersPath, nil)
	req.TLS, err = testMakeConnectionState("testdata/alice.pem",
		"testdata/KeymasterCA.pem")
	errorSent, authData := state.sendFailureToClientIfNonAdmin(w, req)
	if errorSent {
		t.Fatal("error was sent")
	}
	if recorder.Result().StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", recorder.Result().StatusCode)
	}
	if authData.Username != "alice" {
		t.Fatalf("unexpected username: alice, got: %s", authData.Username)
	}
	state.dbDone <- struct{}{}
}

func TestAuthCertPlainUser(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("GET", usersPath, nil)
	req.TLS, err = testMakeConnectionState("testdata/bob.pem",
		"testdata/KeymasterCA.pem")
	errorSent, authData := state.sendFailureToClientIfNonAdmin(w, req)
	if !errorSent {
		t.Error("no error was sent")
	}
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", recorder.Result().StatusCode)
	}
	if authData != nil {
		t.Errorf("expected no authData, got: %v", authData)
	}
	state.dbDone <- struct{}{}
}

func TestAuthCertFakeAdminUser(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("GET", usersPath, nil)
	req.TLS, err = testMakeConnectionState("testdata/alice-fake.pem",
		"testdata/AdminCA.pem")
	errorSent, authData := state.sendFailureToClientIfNonAdmin(w, req)
	if !errorSent {
		t.Error("no error was sent")
	}
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", recorder.Result().StatusCode)
	}
	if authData != nil {
		t.Errorf("expected no authData, got: %v", authData)
	}
	state.dbDone <- struct{}{}
}

func TestEnsurePostAndGetUsernameNotPost(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS, err = testMakeConnectionState("testdata/bill.pem",
		"testdata/KeymasterCA.pem")
	username := state.ensurePostAndGetUsername(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
	if username != "" {
		t.Errorf("expected no username, got: %s", username)
	}
	state.dbDone <- struct{}{}
}

func TestEnsurePostAndGetUsernameNoUsername(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", "/", nil)
	req.TLS, err = testMakeConnectionState("testdata/bill.pem",
		"testdata/KeymasterCA.pem")
	username := state.ensurePostAndGetUsername(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
	if username != "" {
		t.Errorf("expected no username, got: %s", username)
	}
	state.dbDone <- struct{}{}
}

func TestEnsurePostAndGetUsernameBadUsername(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", "/", nil)
	req.TLS, err = testMakeConnectionState("testdata/bill.pem",
		"testdata/KeymasterCA.pem")
	req.Form = make(url.Values)
	req.Form.Add("username", "user%name")
	username := state.ensurePostAndGetUsername(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
	if username != "" {
		t.Errorf("expected no username, got: %s", username)
	}
	state.dbDone <- struct{}{}
}

func TestGenerateBootstrapOtpNotAdminUser(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", generateBoostrapOTPPath, nil)
	req.TLS, err = testMakeConnectionState("testdata/bill.pem",
		"testdata/KeymasterCA.pem")
	req.Form = make(url.Values)
	req.Form.Add("username", "target")
	state.generateBootstrapOTP(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
	state.dbDone <- struct{}{}
}

func TestGenerateBootstrapOtpAdminUser(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	username := "target"
	profile := &userProfile{}
	if err := state.SaveUserProfile(username, profile); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	w := &instrumentedwriter.LoggingWriter{ResponseWriter: recorder}
	req := httptest.NewRequest("POST", generateBoostrapOTPPath, nil)
	req.TLS, err = testMakeConnectionState("testdata/alice.pem",
		"testdata/KeymasterCA.pem")
	req.Form = make(url.Values)
	req.Form.Add("username", username)
	state.generateBootstrapOTP(w, req)
	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d, status: %s, body: %s",
			resp.StatusCode, resp.Status, string(body))
	}
	profile, _, _, err = state.LoadUserProfile(username)
	if err != nil {
		t.Error(err)
	}
	duration := time.Until(profile.BootstrapOTP.ExpiresAt)
	if duration < defaultBootstrapOTPDuration-time.Minute ||
		duration > defaultBootstrapOTPDuration+time.Minute {
		t.Errorf("unexpected duration: %s", duration)
	}
	if len(profile.BootstrapOTP.Sha512Hash) < 1 {
		t.Error("got empty Bootstrap OTP hash")
	}
	state.dbDone <- struct{}{}
}
