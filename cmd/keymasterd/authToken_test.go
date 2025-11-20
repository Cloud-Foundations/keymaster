package main

import (
	"net/http"
	"os"
	"strings"
	"testing"

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
	jwt := ""
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
		if jwt != "" {
			t.Fatal("oops more than jwt founc (this parser could be buggy)")
		}
		jwt = nodeContent
		//t.Logf("%+v", n)
	}
	_, err = state.getAuthInfoFromJWT(jwt,
		"keymaster_webauth_for_cli_identity")
	if err != nil {
		t.Fatal(err)
	}
}
