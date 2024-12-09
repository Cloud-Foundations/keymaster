package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

func TestParseRoleCertGenParams(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	//
	state.Config.Base.AutomationUsers = append(state.Config.Base.AutomationUsers, "role1")
	state.Config.Base.AutomationAdmins = append(state.Config.Base.AutomationAdmins, "admin1")

	//first pass everything OK

	userPemBlock, _ := pem.Decode([]byte(testUserPEMPublicKey))
	b64public := base64.RawURLEncoding.EncodeToString(userPemBlock.Bytes)

	form := url.Values{}
	form.Add("identity", "role1")
	form.Add("requestor_netblock", "127.0.0.1/32")
	form.Add("pubkey", b64public)
	form.Add("target_netblock", "192.168.0.174/32")

	//form.Add("password", validPasswordConst)

	req, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, userErr, err := state.parseRoleCertGenParams(req)
	if err != nil {
		t.Fatal(err)
	}
	if userErr != nil {
		t.Fatal(userErr)
	}

	// now test with broken public key
	form.Set("pubkey", "aGVsbG8gdGhpcyBpcyBzb21laGl0bmcK")
	req2, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, userErr, err = state.parseRoleCertGenParams(req2)
	if err != nil {
		t.Fatal(err)
	}
	if userErr == nil {
		t.Fatal("should have failed because Public key is not valid")
	}

}

func TestRoleRequetingCertGenHandler(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	//
	state.Config.Base.AutomationUsers = append(state.Config.Base.AutomationUsers, "role1")
	state.Config.Base.AutomationAdmins = append(state.Config.Base.AutomationAdmins, "admin1")
	state.Config.Base.AllowedAuthBackendsForCerts = append(state.Config.Base.AllowedAuthBackendsForCerts, proto.AuthTypePassword)
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}

	userPemBlock, _ := pem.Decode([]byte(testUserPEMPublicKey))
	b64public := base64.RawURLEncoding.EncodeToString(userPemBlock.Bytes)
	form := url.Values{}
	form.Add("identity", "role1")
	form.Add("requestor_netblock", "127.0.0.1/32")
	form.Add("pubkey", b64public)
	form.Add("target_netblock", "192.168.0.174/32")

	req, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	cookieVal, err := state.setNewAuthCookie(nil, "admin1", AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr, err := checkRequestHandlerCode(req, state.roleRequetingCertGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

	resp := rr.Result()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// TODO: check body content is actually pem

	//now disable the role as automation use and it should fail
	state.Config.Base.AutomationUsers = []string{}
	req2, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req2.AddCookie(&authCookie)
	req2.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req2.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, err = checkRequestHandlerCode(req, state.roleRequetingCertGenHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}

}

func TestRoleRequetingCertGenHandlerTLSAuth(t *testing.T) {
	state, tmpdir, err := testCreateRuntimeStateWithBothCAs(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	state.Config.Base.AutomationUsers = append(state.Config.Base.AutomationUsers, "role1")
	state.Config.Base.AutomationAdmins = append(state.Config.Base.AutomationAdmins, "admin1")
	state.Config.Base.AllowedAuthBackendsForCerts = append(state.Config.Base.AllowedAuthBackendsForCerts, proto.AuthTypeIPCertificate)

	//Bob id not admin, should fail with forbidden
	req := httptest.NewRequest("POST", getRoleRequestingPath, nil)
	req.TLS, err = testMakeConnectionState("testdata/bob.pem",
		"testdata/KeymasterCA.pem")

	_, err = checkRequestHandlerCode(req, state.roleRequetingCertGenHandler, http.StatusForbidden)
	if err != nil {
		t.Fatal(err)
	}

	//alice is admin... but there is no data, it should fail
	req = httptest.NewRequest("POST", getRoleRequestingPath, nil)
	req.TLS, err = testMakeConnectionState("testdata/alice.pem",
		"testdata/KeymasterCA.pem")
	_, err = checkRequestHandlerCode(req, state.roleRequetingCertGenHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}
	// lets create valid inputs
	userPemBlock, _ := pem.Decode([]byte(testUserPEMPublicKey))
	b64public := base64.RawURLEncoding.EncodeToString(userPemBlock.Bytes)
	form := url.Values{}
	form.Add("identity", "role1")
	form.Add("requestor_netblock", "127.0.0.1/32")
	form.Add("pubkey", b64public)
	form.Add("target_netblock", "192.168.0.174/32")

	req2, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req2.TLS, err = testMakeConnectionState("testdata/alice.pem",
		"testdata/KeymasterCA.pem")
	rr, err := checkRequestHandlerCode(req2, state.roleRequetingCertGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	// TODO: check body response is actual cert to get a cert
	resp := rr.Result()
	pemData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	if block.Type != "CERTIFICATE" {
		t.Fatalf("no CERTIFICATE found")
	}
	rrCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	req3, err := createKeyBodyRequest("POST", "/certgen/role1?type=x509", testUserPEMPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	req3.RemoteAddr = "127.0.0.1:12345"
	var fakePeerCertificates []*x509.Certificate
	var fakeVerifiedChains [][]*x509.Certificate
	fakePeerCertificates = append(fakePeerCertificates, rrCert)
	fakeVerifiedChains = append(fakeVerifiedChains, fakePeerCertificates)
	connectionState := &tls.ConnectionState{
		VerifiedChains:   fakeVerifiedChains,
		PeerCertificates: fakePeerCertificates}
	req3.TLS = connectionState
	_, err = checkRequestHandlerCode(req3, state.certGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	// and now use the cert to
}

func TestRefreshRoleRequetingCertGenHandler(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	//
	state.Config.Base.AutomationUsers = append(state.Config.Base.AutomationUsers, "role1")
	state.Config.Base.AutomationAdmins = append(state.Config.Base.AutomationAdmins, "admin1")
	state.Config.Base.AllowedAuthBackendsForCerts = append(state.Config.Base.AllowedAuthBackendsForCerts, proto.AuthTypePassword)
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}

	userPub, err := getPubKeyFromPem(testUserPEMPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	netblock := net.IPNet{
		IP:   net.ParseIP("127.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblock2 := net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblockList := []net.IPNet{netblock, netblock2}

	initialrrParams := roleRequestingCertGenParams{
		Role:               "role1",
		Duration:           time.Hour,
		RequestorNetblocks: netblockList,
		UserPub:            userPub,
	}
	_, rrcert, err := state.withParamsGenerateRoleRequestingCert(&initialrrParams)
	if err != nil {
		t.Fatal(err)
	}

	userPemBlock, _ := pem.Decode([]byte(testUserPEMPublicKey))
	b64public := base64.RawURLEncoding.EncodeToString(userPemBlock.Bytes)
	form := url.Values{}
	form.Add("pubkey", b64public)

	req, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	var fakePeerCertificates []*x509.Certificate
	var fakeVerifiedChains [][]*x509.Certificate
	fakePeerCertificates = append(fakePeerCertificates, rrcert)
	fakeVerifiedChains = append(fakeVerifiedChains, fakePeerCertificates)
	connectionState := &tls.ConnectionState{
		VerifiedChains:   fakeVerifiedChains,
		PeerCertificates: fakePeerCertificates}
	req.TLS = connectionState

	//TODO add fail value
	_, err = checkRequestHandlerCode(req, state.refreshRoleRequestingCertGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

}
