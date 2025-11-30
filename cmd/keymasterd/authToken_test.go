package main

import (
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"golang.org/x/net/html"
)

// See if we can start getting some coverage here
func TestShowAuthTokenHandlerBase(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	err = state.loadTemplates()
	if err != nil {
		t.Fatal(err)
	}

	state.Config.Base.AllowedAuthBackendsForCerts = append(state.Config.Base.AllowedAuthBackendsForCerts, proto.AuthTypePassword)
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}
	state.Config.Base.WebauthTokenForCliLifetime = time.Hour

	// Get request
	req, err := createKeyBodyRequest("POST", "/certgen/username", testEd25519PublicSSH, "")
	if err != nil {
		t.Fatal(err)
	}
	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)

	rr, err := checkRequestHandlerCode(req, state.ShowAuthTokenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

	resp := rr.Result()
	doc, err := html.Parse(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// We should be actually parsing the doc,
	// but we are only searching for the first node that looks like a
	// jwt... this is very fragile
	authToken := ""
	for n := range doc.Descendants() {
		if n.Type != html.TextNode {
			continue
		}
		nodeContent := n.Data
		nodeContent = strings.TrimLeft(nodeContent, " ")
		nodeContent = strings.TrimRight(nodeContent, " ")
		if !strings.HasPrefix(nodeContent, "ey") {
			continue
		}
		if authToken != "" {
			t.Fatal("oops more than jwt founc (this parser could be buggy)")
		}
		authToken = nodeContent
		//t.Logf("%+v", n)
	}
	_, err = state.getAuthInfoFromJWT(authToken,
		"keymaster_webauth_for_cli_identity")
	if err != nil {
		t.Fatal(err)
	}

}

func TestSendAuthDocumentHandlerBase(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.Config.Base.WebauthTokenForCliLifetime = time.Hour
	//generate authDoc
	testUsername := "testuser"
	authToken, err := state.generateAuthJWT(testUsername)
	if err != nil {
		t.Fatal(err)
	}

	//Allow Password auth for webui
	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypePassword)

	//generate request
	tokenForm := url.Values{}
	tokenForm.Add("token", authToken)
	tokenForm.Add("port", "12345")
	t.Logf("tokenVal=%s", authToken)

	tokenReq, err := http.NewRequest("POST", idpOpenIDCTokenPath, strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenReq.Header.Add("Content-Length", strconv.Itoa(len(tokenForm.Encode())))
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	cookieVal, err := state.setNewAuthCookie(nil, testUsername, AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cookieval=%s", cookieVal)
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	tokenReq.AddCookie(&authCookie)

	tokenRR, err := checkRequestHandlerCode(tokenReq, state.SendAuthDocumentHandler, http.StatusPermanentRedirect)
	if err != nil {
		t.Fatal(err)
	}
	resp := tokenRR.Result()
	//t.Logf("tokenRR=%+v", resp.Header)
	location, ok := resp.Header["Location"]
	if !ok {
		t.Fatal("no location returned")
	}
	//t.Logf("redir location=%s", location)
	if len(location) != 1 {
		t.Fatal("should have returned a single redirection location")
	}
	parsedLocation, err := url.Parse(location[0])
	if err != nil {
		t.Fatal(err)
	}
	// should we make this 127.0.0.1 instead?
	if parsedLocation.Hostname() != "localhost" {
		t.Fatalf("hostname is NOT localhost it")
	}
	if parsedLocation.Port() != "12345" {
		t.Fatalf("port mismatch")
	}
	q := parsedLocation.Query()
	resultAuthToken := q.Get("auth_cookie")
	authinfo, err := state.getAuthInfoFromAuthJWT(resultAuthToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("authinfo=%+v", authinfo)

}
