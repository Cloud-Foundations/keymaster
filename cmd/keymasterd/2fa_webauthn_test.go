package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"

	oldproto "github.com/duo-labs/webauthn/protocol"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestWebAuthnRegistrationBegin(t *testing.T) {

	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypeU2F)

	state.signerPublicKeyToKeymasterKeys()

	// cviecco -> probablt dont need tempdir
	dir, err := os.MkdirTemp("", "example")
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
	// end of copy
	logger = state.logger

	u2fAppID = "https://" + state.HostIdentity // this should include the port...but not needed for this test as we assume 443
	state.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Keymaster Server", // Display Name for your site
		RPID:          state.HostIdentity, // Generally the domain name for your site
		RPOrigins:     []string{u2fAppID}, // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})
	if err != nil {
		t.Fatal(err)
	}

	// end of setup

	req, err := http.NewRequest("GET", webAutnRegististerRequestPath+"username", nil)
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

	regData, err := checkRequestHandlerCode(req, state.webauthnBeginRegistration, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	/*
	   resultAccessToken := newTOTPPageTemplateData{}
	*/
	body := regData.Result().Body
	var b bytes.Buffer
	_, err = io.Copy(&b, body)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("regdata=%s\n", b.String())

	// This is the round trip
	var out protocol.CredentialAssertion
	if err = json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatal(err)
	}

	/*
	   err = json.NewDecoder(body).Decode(&resultAccessToken)
	   if err != nil {
	           t.Fatal(err)
	   }
	   t.Logf("totpDataToken='%+v'", resultAccessToken)
	*/

	/*
			Example post for finalization:
		        {
			"{\"id\":\"_N2M7t9Qe2rwS4asNZ15I4Thd-nkXow6_lyDT6CURM3gD1sAq0FyMnf8NDOARMWMjjNgPfeHpPWP0Q8nkx-v7pNRuR0IwRHkvZeZxaV3Ql3HFigByVOhuB3OCq2em8Ve\",\"rawId\":\"_N2M7t9Qe2rwS4asNZ15I4Thd-nkXow6_lyDT6CURM3gD1sAq0FyMnf8NDOARMWMjjNgPfeHpPWP0Q8nkx-v7pNRuR0IwRHkvZeZxaV3Ql3HFigByVOhuB3OCq2em8Ve\",\"type\":\"public-key\",\"response\":{\"attestationObject\":\"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAADlwAAAAAAAAAAAAAAAAAAAAAAYPzdjO7fUHtq8EuGrDWdeSOE4Xfp5F6MOv5cg0-glETN4A9bAKtBcjJ3_DQzgETFjI4zYD33h6T1j9EPJ5Mfr-6TUbkdCMER5L2XmcWld0JdxxYoAclTobgdzgqtnpvFXqUBAgMmIAEhWCBwm_S46LuncSKubWLGS7236xBQyY-Ptg0dTKpOmddRMCJYIG02ZJischNpyUqMXRdiJfBW2kDmG3TROzKzHHBHmLlp\",\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiJlTW1Ca0gxQ05KZzFsbGRQb3ZXQUN6R0pMZUpYRHZndmViUXIycDRxdWNVIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6MzM0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0\"}}": ""
		}
	*/
	state.dbDone <- struct{}{}
}

func TestWebAuthnLoginBegin(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(passwdFile.Name()) // clean up

	state.localAuthData = make(map[string]localUserData)

	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypeU2F)

	state.signerPublicKeyToKeymasterKeys()

	// cviecco -> probablt dont need tempdir
	dir, err := os.MkdirTemp("", "example")
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
	// end of copy
	logger = state.logger

	u2fAppID = "https://" + state.HostIdentity // this should include the port...but not needed for this test as we assume 443
	state.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Keymaster Server", // Display Name for your site
		RPID:          state.HostIdentity, // Generally the domain name for your site
		RPOrigins:     []string{u2fAppID}, // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})
	if err != nil {
		t.Fatal(err)
	}
	// add user to profile
	username := "username"
	profile := &userProfile{
		WebauthnData: make(map[int64]*webauthAuthData),
		U2fAuthData:  make(map[int64]*u2fAuthData),
	}
	profile.FixupCredential(username, "")
	credential := webauthn.Credential{
		ID:        []byte{0x01, 0x02},
		PublicKey: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	err = profile.AddWebAuthnCredential(credential)
	if err != nil {
		t.Fatal(err)
	}

	if err := state.SaveUserProfile(username, profile); err != nil {
		t.Fatal(err)
	}
	// end of setup

	req, err := http.NewRequest("GET", webAuthnAuthBeginPath+"username", nil)
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

	regData, err := checkRequestHandlerCode(req, state.webauthnAuthLogin, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	body := regData.Result().Body
	var b bytes.Buffer
	_, err = io.Copy(&b, body)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("regdata=%s\n", b.String())

	// TODO: we are jus manually doing the json parsing here,
	// we should be actually be using the client code
	var compatClient oldproto.CredentialAssertion
	if err = json.Unmarshal(b.Bytes(), &compatClient); err != nil {
		t.Fatal(err)
	}

	state.dbDone <- struct{}{}
}
