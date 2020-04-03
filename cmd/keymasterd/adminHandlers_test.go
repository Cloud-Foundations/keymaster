package main

import (
	//	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	//	"fmt"
	//	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	//	"net/url"
	"os"
	//	"strconv"
	//	"strings"
	"testing"

	//	"github.com/Cloud-Foundations/keymaster/keymasterd/eventnotifier"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	//	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
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
	state.caCertDer, err = generateCADer(state, state.Signer)
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
	errorSent, username := state.sendFailureToClientIfNonAdmin(w, req)
	if errorSent {
		return
	}
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", recorder.Result().StatusCode)
	}
	if username != "" {
		t.Errorf("expected no username, got: %s", username)
	}
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
	errorSent, username := state.sendFailureToClientIfNonAdmin(w, req)
	if errorSent {
		t.Fatal("error was sent")
	}
	if recorder.Result().StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", recorder.Result().StatusCode)
	}
	if username != "alice" {
		t.Fatalf("unexpected username: alice, got: %s", username)
	}
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
	errorSent, username := state.sendFailureToClientIfNonAdmin(w, req)
	if !errorSent {
		t.Error("no error was sent")
	}
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", recorder.Result().StatusCode)
	}
	if username != "" {
		t.Errorf("expected no username, got: %s", username)
	}
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
	errorSent, username := state.sendFailureToClientIfNonAdmin(w, req)
	if !errorSent {
		t.Error("no error was sent")
	}
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d", recorder.Result().StatusCode)
	}
	if username != "" {
		t.Errorf("expected no username, got: %s", username)
	}
}
