package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Cloud-Foundations/Dominator/lib/log/debuglogger"
	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
	"github.com/Cloud-Foundations/keymaster/keymasterd/eventnotifier"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/pwauth/htpassword"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

// copied from lib/certgen/cergen_test.go
const testSignerPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAv2J464KoYbODMIbtkTV58g6/0QTdUIYgOwnzPdaMNVtCOxTi
QDIWEbzqv1HEP9hfzuaSKHUHs/91e4Jj2qZghSwPHLG7TKzu+/CRK9sa9jvoGEVx
g6yjibPndTGuLVptZCcOIcHEXViP4iraI6dybiGDlmeF92WQJdI7l4Esg4W4Wp17
JFWNHbylKoFB0fe2b4q5pzaXMBwNue4BKKvua51NBctRy4LZYwiGvVJplEbjBU7v
wCAS0X4m72y2JvKog9/HfGKo2rZ9se0wFe9mMkjj0wuKkDh91pOzsBZ/0PW0zHci
2q9yJVxF0b41e9+raXa8kvRjxF7EEAuUr9Ov2wIDAQABAoIBAQCPmP4rjyRx8jQr
9AFKY7p00XZBCYpZAdorEiMtMc6PtkJyfA/qpOoEMyBbnqlGUj5Iyp29t1mpR7LJ
kiMECrP/F/jaycxEErlZ1b3HDyYivP4/P9OVPbKS/qZbO4R5yRCtBdTHpVCFzY5f
31E/UUM9uO23q0NMRisrBZvq6GQS5bPIbV/JHJIj1Xd65pZQKQMlRKdXnQGWANV6
4i6Yjcy8v/hqI4wxiwxGlAC26+d1Ow4sdHsMiRmA31vhJNMktdVfT3emyiIlLwoi
Oolbak9CpV2bvtN6iL0Hy4ek0TZp7QPzp7MT4Bhcf8jj9ykxL51SplJoOh2xVwfF
U4aaf1mJAoGBAPKP3an+LFPl8+Re8kVJay7JQrNOIzuoDsDbfhVQMJ9KuodGBz8U
YaUeK8iYZFRuYB/OuIqoDiFnlcdC441+M9VRMhuKwq1rLUOz92esyfiwn8CNzEnT
bJKDPvLocGtpRrN+2iqy+/ySk0IX7NUtsB2/8KXLXImY3ecTafjjqv4dAoGBAMn8
yM03RuBOTXsxWRjPIGBniH0mZG+7KdEbBGmhvhoZ8+uneXJvNL+0xswnf6S4r1tm
mEWM1PldE0tPbRID148Mm2H+tCv7IwtpXSRTKEb175Xkj+pIcFtBC1bkGdNv8DJW
BdkKVnDD2h6rND1IOHatBNjW+CO+2R3aZPUxBGRXAoGAfWu0QzTg+NS7QodxoC/x
UvTQH2S0xSEF1+TmkeCv832xa0bjclN4lec+3m8l2Z5k5619MHzrKYylHq5QeRYb
eR6N2T3rob38XriMobfviz7Qq8DmM/o1dqCUiQd1MaTy4NcjudZog1XK/O7gD+6a
1RctOJ0pkSBRBS29qusVvGUCgYEAtvsDRbUvxf/pfRKlbi4lXHAuW4GuNvHM3hul
kbPurWKZcAAVqy9HD+xKs6OMpMKSSTDV/RupzAUfd3gKjOliG7sGAG5m9fjaNHpM
4J1cvXwKgTW/kjPxZRm1lg+pvbuIU3FOduJAkIM8U9Aw0NteG1R+MZn8zRUVR1AT
aXPwUJ0CgYEA6Fpq8/MFJyzpcvlxkZSfZOVFmkDbE3+UYkB0WAR0X7sTdN74nrTf
RnmMXhcdJ7cCPL6LJpN82h62XrLVwl7zEBXnVfhSsXil1yYHHI5sGXbUFRzaNXNl
KgeanQGV/sG+nd/67uvHhZbifHVDY/ifsNBnYrlpu6q3p+zhQydfkLE=
-----END RSA PRIVATE KEY-----`

const testUserSSHPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI09fpMWTeYw7/EO/+FywS/sghNXdTeTWxX7K2N17owsQJX8s76LGVIdVeYrWg4QSmYlpf6EVSCpx/fbCazrsG7FJVTRhExzFbRT9asmvzS+viXSbSvnavhOz/paihyaMsVPKVv24vF6MOs8DgfwehcKCPjKoIPnlYXZaZcy05KOcZmsvYu2kNOP6sSjDFF+ru+T+DLp3DUGw+MPr45IuR7iDnhXhklqyUn0d7ou0rOHXz9GdHIzpr+DAoQGmTDkpbQEo067Rjfu406gYL8pVFD1F7asCjU39llQCcU/HGyPym5fa29Nubw0dzZZXGZUVFalxo02YMM7P9I6ZjeCsv camilo_viecco1@mon-sre-dev.ash2.symcpe.net`

// The next was extracted from the testUserPrivateKey above : openssl rsa -in userkey.pem -pubout
const testUserPEMPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyNPX6TFk3mMO/xDv/hcs
Ev7IITV3U3k1sV+ytjde6MLECV/LO+ixlSHVXmK1oOEEpmJaX+hFUgqcf32wms67
BuxSVU0YRMcxW0U/WrJr80vr4l0m0r52r4Ts/6WoocmjLFTylb9uLxejDrPA4H8H
oXCgj4yqCD55WF2WmXMtOSjnGZrL2LtpDTj+rEowxRfq7vk/gy6dw1BsPjD6+OSL
ke4g54V4ZJaslJ9He6LtKzh18/RnRyM6a/gwKEBpkw5KW0BKNOu0Y37uNOoGC/KV
RQ9Re2rAo1N/ZZUAnFPxxsj8puX2tvTbm8NHc2WVxmVFRWpcaNNmDDOz/SOmY3gr
LwIDAQAB
-----END PUBLIC KEY-----`

// This DB has user 'username' with password 'password'
const userdbContent = `username:$2y$05$D4qQmZbWYqfgtGtez2EGdOkcNne40EdEznOqMvZegQypT8Jdz42Jy`

type loginTestVector struct {
	Username *string
	Password *string
}

var validUsernameConst = "username"
var validPasswordConst = "password"
var emptyStringConst = ""

var loginFailValues = []loginTestVector{
	{Username: &validUsernameConst, Password: &validUsernameConst}, //bad password
	{Username: &validPasswordConst, Password: &validPasswordConst}, //bad username
	{Username: &validUsernameConst, Password: &emptyStringConst},
	{Username: &emptyStringConst, Password: &validPasswordConst},
	{Username: nil, Password: &validPasswordConst},
	{Username: &validUsernameConst, Password: nil},
}

func init() {
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger = debuglogger.New(slogger)
	eventNotifier = eventnotifier.New(logger)
}

func createKeyBodyRequest(method, urlStr, filedata, durationString string) (*http.Request, error) {
	//create attachment....
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	//
	fileWriter, err := bodyWriter.CreateFormFile("pubkeyfile", "somefilename.pub")
	if err != nil {
		fmt.Println("error writing to buffer")
		//t.Fatal(err)
		return nil, err
	}
	fh := strings.NewReader(filedata)

	//iocopy
	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		//t.Fatal(err)
		return nil, err
	}
	if durationString == "" {
		durationString = "1h"
	}
	err = bodyWriter.WriteField("duration", durationString)
	if err != nil {
		//t.Fatal(err)
		return nil, err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest(method, urlStr, bodyBuf)
	if err != nil {
		//t.Fatal(err)
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	return req, nil
}

func createBasicAuthRequstWithKeyBody(method, urlStr, username, password, filedata string) (*http.Request, error) {

	req, err := createKeyBodyRequest(method, urlStr, filedata, "")
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	return req, nil
}

func setupPasswdFile() (f *os.File, err error) {
	tmpfile, err := ioutil.TempFile("", "userdb_test")
	if err != nil {
		return nil, err
	}
	//from this moment on.. we need to remove the tmpfile only on error conditions

	if _, err := tmpfile.Write([]byte(userdbContent)); err != nil {
		os.Remove(tmpfile.Name())
		return nil, err
	}
	if err := tmpfile.Close(); err != nil {
		os.Remove(tmpfile.Name())
		return nil, err
	}
	return tmpfile, nil
}

func setupValidRuntimeStateSigner(t *testing.T) (
	*RuntimeState, *os.File, error) {
	logger := testlogger.New(t)
	state := RuntimeState{logger: logger}
	//load signer
	signer, err := getSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		//log.Printf("Cannot parse Priave Key file")
		return nil, nil, err
	}
	state.Signer = signer
	state.signerPublicKeyToKeymasterKeys()

	//for x509
	state.caCertDer, err = generateCADer(&state, signer)
	if err != nil {
		return nil, nil, err
	}

	passwdFile, err := setupPasswdFile()
	if err != nil {
		return nil, nil, err
	}
	state.passwordChecker, err = htpassword.New(passwdFile.Name(), logger)
	if err != nil {
		return nil, nil, err
	}

	state.totpLocalRateLimit = make(map[string]totpRateLimitInfo)
	return &state, passwdFile, nil
}

func TestSuccessFullSigningSSH(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	// Get request
	req, err := createBasicAuthRequstWithKeyBody("POST", "/certgen/username", "username", "password", testUserSSHPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.certGenHandler,
		http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}

	// now we check using login auth + cookies
	// For now just inject cookie into space

	cookieReq, err := createKeyBodyRequest("POST", "/certgen/username", testUserSSHPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}

	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	cookieReq.AddCookie(&authCookie)

	_, err = checkRequestHandlerCode(cookieReq, state.certGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	// TODO check for the contents of the successful response...
}

func TestSuccessFullSigningX509(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	// Get request
	req, err := createBasicAuthRequstWithKeyBody("POST", "/certgen/username?type=x509", "username", "password", testUserPEMPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.certGenHandler,
		http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// TODO: Check the response body is what we expect.

	//And also test with cookies
	cookieReq, err := createKeyBodyRequest("POST", "/certgen/username?type=x509", testUserPEMPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}

	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	cookieReq.AddCookie(&authCookie)

	_, err = checkRequestHandlerCode(cookieReq, state.certGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSuccessFullSigningX509BadLDAPNoGroups(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.Config.UserInfo.Ldap.LDAPTargetURLs = "ldapXX://localhost"

	// Get request
	req, err := createBasicAuthRequstWithKeyBody("POST", "/certgen/username?type=x509", "username", "password", testUserPEMPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.certGenHandler,
		http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// TODO: Check the response body is what we expect.

	//And also test with cookies
	cookieReq, err := createKeyBodyRequest("POST", "/certgen/username?type=x509", testUserPEMPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}

	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	cookieReq.AddCookie(&authCookie)

	_, err = checkRequestHandlerCode(cookieReq, state.certGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFailFullSigningX509GroupsBadLDAPNoGroups(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.Config.UserInfo.Ldap.LDAPTargetURLs = "ldapXX://localhost"

	// Get request
	req, err := createBasicAuthRequstWithKeyBody("POST", "/certgen/username?type=x509&addGroups=true", "username", "password", testUserPEMPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.certGenHandler,
		http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// TODO: Check the response body is what we expect.

	//And also test with cookies
	cookieReq, err := createKeyBodyRequest("POST", "/certgen/username?type=x509&addGroups=true", testUserPEMPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}

	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	cookieReq.AddCookie(&authCookie)

	_, err = checkRequestHandlerCode(cookieReq, state.certGenHandler, http.StatusInternalServerError)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFailCertgenDurationTooLong(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	// Get request
	req, err := createBasicAuthRequstWithKeyBody("POST", "/certgen/username", "username", "password", testUserSSHPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.certGenHandler,
		http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}

	// now we check using login auth + cookies
	// For now just inject cookie into space

	cookieReq, err := createKeyBodyRequest("POST", "/certgen/username", testUserSSHPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}

	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	cookieReq.AddCookie(&authCookie)

	_, err = checkRequestHandlerCode(cookieReq, state.certGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	// Now since we know it is correct.. we try again with invalid durations
	badValues := []string{"100h", "10X"}
	for _, invalidValue := range badValues {
		tooLongReqSSH, err := createKeyBodyRequest("POST", "/certgen/username", testUserSSHPublicKey, invalidValue)
		if err != nil {
			t.Fatal(err)
		}
		tooLongReqSSH.AddCookie(&authCookie)
		_, err = checkRequestHandlerCode(tooLongReqSSH, state.certGenHandler, http.StatusBadRequest)
		if err != nil {
			t.Fatal(err)
		}

		tooLongReqX509, err := createKeyBodyRequest("POST", "/certgen/username?type=x509", testUserPEMPublicKey, invalidValue)
		if err != nil {
			t.Fatal(err)
		}
		tooLongReqX509.AddCookie(&authCookie)
		_, err = checkRequestHandlerCode(tooLongReqX509, state.certGenHandler, http.StatusBadRequest)
		if err != nil {
			t.Fatal(err)
		}
	}

}

func TestFailSingingExpiredCookie(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	//Fist we ensure OK is working
	cookieReq, err := createKeyBodyRequest("POST", "/certgen/username?type=x509", testUserPEMPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}

	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	cookieReq.AddCookie(&authCookie)

	_, err = checkRequestHandlerCode(cookieReq, state.certGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	// Now expire the cookie and retry
	// THis tests needs to be rewritten to have and expired token... need to figure out
	// the best way to do this.
	/*
		state.authCookie[cookieVal] = authInfo{IssuedAt: time.Now(), Username: "username", AuthType: AuthTypeU2F, ExpiresAt: time.Now().Add(-120 * time.Second)}
		_, err = checkRequestHandlerCode(cookieReq, state.certGenHandler, http.StatusUnauthorized)
		if err != nil {
			t.Fatal(err)
		}
	*/
	// TODO check that body is actually empty
}

func TestFailSinginUnexpectedCookie(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	cookieReq, err := createKeyBodyRequest("POST", "/certgen/username?type=x509", testUserPEMPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: "nonmatchingvalue"}
	cookieReq.AddCookie(&authCookie)

	// Now expire the cookie and retry
	_, err = checkRequestHandlerCode(cookieReq, state.certGenHandler, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// TODO check that body is actually empty
}

func checkRequestHandlerCode(req *http.Request, handlerFunc http.HandlerFunc, expectedStatus int) (*httptest.ResponseRecorder, error) {
	rr := httptest.NewRecorder()
	l := httpLogger{}
	handler := instrumentedwriter.NewLoggingHandler(http.HandlerFunc(handlerFunc), l)

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != expectedStatus {
		errStr := fmt.Sprintf("handler returned wrong status code: got %v want %v",
			status, expectedStatus)
		err := errors.New(errStr)
		return nil, err
	}
	return rr, nil
}

func TestPublicHandleLoginForm(t *testing.T) {
	state := RuntimeState{logger: testlogger.New(t)}
	//load signer
	signer, err := getSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		//log.Printf("Cannot parse Priave Key file")
		//return runtimeState, err
		t.Fatal(err)
	}
	state.Signer = signer
	state.signerPublicKeyToKeymasterKeys()
	urlList := []string{"/public/loginForm", "/public/x509ca"}
	err = state.loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range urlList {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
			//return nil, err
		}
		_, err = checkRequestHandlerCode(req, state.publicPathHandler, http.StatusOK)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest("GET", "/public/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.publicPathHandler, http.StatusNotFound)
	if err != nil {
		t.Fatal(err)
	}
}

// returns true if it has a valid cookie that is found on the runtimestate...
// probably can be replaced by something calling checkAuth once that understands the login
// form.
func checkValidLoginResponse(resp *http.Response, state *RuntimeState, username string) bool {
	//get cookies
	var authCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}
	if authCookie == nil {
		return false
	}
	info, err := state.getAuthInfoFromAuthJWT(authCookie.Value)
	if err != nil {
		return false
	}
	if info.Username != username {
		return false
	}

	// TODO: add check for expiration.
	return true

}

func TestLoginAPIBasicAuth(t *testing.T) {
	state, tmpdir, err := newTestingState(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	//load signer
	signer, err := getSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	state.Signer = signer
	state.signerPublicKeyToKeymasterKeys()
	passwdFile, err := setupPasswdFile()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.passwordChecker, err = htpassword.New(passwdFile.Name(), logger)
	if err != nil {
		t.Fatal(err)
	}
	err = initDB(state)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "/api/v0/login", nil)
	if err != nil {
		t.Fatal(err)
		//return nil, err
	}
	req.SetBasicAuth(validUsernameConst, validPasswordConst)
	rr, err := checkRequestHandlerCode(req, state.loginHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	//TODO: check for existence of login cookie!
	if !checkValidLoginResponse(rr.Result(), state, validUsernameConst) {
		t.Fatal(err)
	}
	//now we check for failed auth
	for _, testVector := range loginFailValues {
		//there are no nil values in basic auth
		if testVector.Password == nil {
			continue
		}
		if testVector.Username == nil {
			continue
		}
		req.SetBasicAuth(*testVector.Username, *testVector.Password)
		_, err = checkRequestHandlerCode(req, state.loginHandler, http.StatusUnauthorized)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoginAPIFormAuth(t *testing.T) {
	state, tmpdir, err := newTestingState(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	//load signer
	signer, err := getSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	state.Signer = signer
	state.signerPublicKeyToKeymasterKeys()
	passwdFile, err := setupPasswdFile()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.passwordChecker, err = htpassword.New(passwdFile.Name(), logger)
	if err != nil {
		t.Fatal(err)
	}
	err = initDB(state)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Add("username", validUsernameConst)
	form.Add("password", validPasswordConst)
	req, err := http.NewRequest("POST", proto.LoginPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	// TODO: add thest with multipart/form-data support and test
	//req.Header.Add("Content-Type", "multipart/form-data")
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr, err := checkRequestHandlerCode(req, state.loginHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	// TODO: check for existence of login cookie!
	if !checkValidLoginResponse(rr.Result(), state, validUsernameConst) {
		t.Fatal(err)
	}
	// test with form AND with json return
	req.Header.Add("Accept", "application/json")
	jsonrr, err := checkRequestHandlerCode(req, state.loginHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	if !checkValidLoginResponse(jsonrr.Result(), state, validUsernameConst) {
		t.Fatal(err)
	}
	loginResponse := proto.LoginResponse{}
	body := jsonrr.Result().Body
	err = json.NewDecoder(body).Decode(&loginResponse)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("loginResponse='%+v'", loginResponse)
	// now we check for failed auth
	for _, testVector := range loginFailValues {
		form := url.Values{}
		if testVector.Password != nil {
			form.Add("password", *testVector.Password)
		}
		if testVector.Username != nil {
			form.Add("username", *testVector.Username)
		}
		req, err := http.NewRequest("POST", proto.LoginPath, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		t.Logf("form='%s'", form.Encode())
		//req.SetBasicAuth(*testVector.Username, *testVector.Password)
		_, err = checkRequestHandlerCode(req, state.loginHandler, http.StatusUnauthorized)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestProfileHandlerTemplate(t *testing.T) {
	state := RuntimeState{logger: testlogger.New(t)}
	//load signer
	signer, err := getSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	state.Signer = signer
	state.signerPublicKeyToKeymasterKeys()

	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}
	err = initDB(&state)
	if err != nil {
		t.Fatal(err)
	}
	err = state.loadTemplates()
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "/profile/", nil)
	if err != nil {
		t.Fatal(err)
		//return nil, err
	}
	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeAny)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)

	_, err = checkRequestHandlerCode(req, state.profileHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	//TODO: verify HTML output
}

func TestU2fTokenManagerHandlerUpdateSuccess(t *testing.T) {
	state := RuntimeState{logger: testlogger.New(t)}
	//load signer
	signer, err := getSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	state.Signer = signer
	state.signerPublicKeyToKeymasterKeys()

	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}
	err = initDB(&state)
	if err != nil {
		t.Fatal(err)
	}

	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeAny)
	if err != nil {
		t.Fatal(err)
	}
	//cookieReq.AddCookie(&authCookie)
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}

	const newName = "New./-X"
	const oldName = "Old"

	profile := &userProfile{}
	profile.U2fAuthData = make(map[int64]*u2fAuthData)
	profile.U2fAuthData[0] = &u2fAuthData{Name: oldName}
	err = state.SaveUserProfile("username", profile)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("username", "username")
	//form.Add("password", validPasswordConst)
	form.Add("index", "0")
	form.Add("name", newName)
	form.Add("action", "Update")

	req, err := http.NewRequest("POST", u2fTokenManagementPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&authCookie)
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	val, err := checkRequestHandlerCode(req, state.u2fTokenManagerHandler, http.StatusOK)
	if err != nil {
		t.Log(val)
		t.Fatal(err)
	}
	// Todo... check against the FS.
	profile, _, _, err = state.LoadUserProfile("username")
	if err != nil {
		t.Fatal(err)
	}
	if profile.U2fAuthData[0].Name != newName {
		t.Fatal("update not successul")
	}
}

func TestU2fTokenManagerHandlerDeleteNotAdmin(t *testing.T) {
	var state RuntimeState
	//load signer
	signer, err := getSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	state.Signer = signer

	// login as user username
	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeAny)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}

	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}
	err = initDB(&state)
	if err != nil {
		t.Fatal(err)
	}

	profile := &userProfile{}
	profile.U2fAuthData = make(map[int64]*u2fAuthData)
	profile.U2fAuthData[0] = &u2fAuthData{Name: "name1", Enabled: false}
	profile.U2fAuthData[1] = &u2fAuthData{Name: "name2", Enabled: false}

	// 2 U2F's in differentuser's profile
	err = state.SaveUserProfile("differentuser", profile)
	if err != nil {
		t.Fatal(err)
	}

	// Set up request to delete first u2f from "differentuser"
	form := url.Values{}
	form.Add("username", "differentuser")
	form.Add("index", "0")
	form.Add("action", "Delete")

	req, err := http.NewRequest("POST", u2fTokenManagementPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&authCookie)
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	val, err := checkRequestHandlerCode(req, state.u2fTokenManagerHandler, http.StatusUnauthorized)
	if err != nil {
		t.Log(val)
		t.Fatal(err)
	}
	// Todo... check against the FS.
	profile, _, _, err = state.LoadUserProfile("differentuser")
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.U2fAuthData) != 2 {
		t.Fatal("delete should not have succeeded")
	}
}

func TestU2fTokenManagerHandlerDeleteSuccess(t *testing.T) {
	state := RuntimeState{logger: testlogger.New(t)}
	//load signer
	signer, err := getSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	state.Signer = signer
	state.signerPublicKeyToKeymasterKeys()

	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeAny)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}

	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}
	err = initDB(&state)
	if err != nil {
		t.Fatal(err)
	}

	profile := &userProfile{}
	profile.U2fAuthData = make(map[int64]*u2fAuthData)
	profile.U2fAuthData[0] = &u2fAuthData{Name: "name1", Enabled: false}
	profile.U2fAuthData[1] = &u2fAuthData{Name: "name2", Enabled: false}

	err = state.SaveUserProfile("username", profile)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("username", "username")
	//form.Add("password", validPasswordConst)
	form.Add("index", "0")
	form.Add("action", "Delete")

	req, err := http.NewRequest("POST", u2fTokenManagementPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&authCookie)
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	val, err := checkRequestHandlerCode(req, state.u2fTokenManagerHandler, http.StatusOK)
	if err != nil {
		t.Log(val)
		t.Fatal(err)
	}
	// Todo... check against the FS.
	profile, _, _, err = state.LoadUserProfile("username")
	if err != nil {
		t.Fatal(err)
	}
	//if len(state.userProfile["username"].U2fAuthData) != 1 {
	if len(profile.U2fAuthData) != 1 {
		t.Fatal("update not successul")
	}
}
