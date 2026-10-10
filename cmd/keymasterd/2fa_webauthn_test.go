package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"

	oldproto "github.com/duo-labs/webauthn/protocol"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
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
	state.HostIdentity = "testHost.example.com"
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
	state.HostIdentity = "testHost.example.com"
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

// The next sections where added via Claude code (Opus 5.5)
// makeTestWebauthnCredential creates a new P-256 key pair and a webauthn
// credential (non fido-u2f) holding its COSE encoded public key.
func makeTestWebauthnCredential(t *testing.T) (*ecdsa.PrivateKey, webauthn.Credential) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coseKey := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: privKey.PublicKey.X.FillBytes(make([]byte, 32)),
		YCoord: privKey.PublicKey.Y.FillBytes(make([]byte, 32)),
	}
	pubKeyBytes, err := webauthncbor.Marshal(coseKey)
	if err != nil {
		t.Fatal(err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatal(err)
	}
	credential := webauthn.Credential{
		ID:              credentialID,
		PublicKey:       pubKeyBytes,
		AttestationType: "none",
		Flags: webauthn.NewCredentialFlags(
			protocol.FlagUserPresent | protocol.FlagAttestedCredentialData),
		Authenticator: webauthn.Authenticator{
			AAGUID: make([]byte, 16),
		},
	}
	return privKey, credential
}

// makeTestAssertionResponse builds the JSON body an authenticator/browser
// would POST to finish a webauthn login for the given challenge.
func makeTestAssertionResponse(t *testing.T, privKey *ecdsa.PrivateKey,
	credentialID []byte, challenge string, rpID string, origin string,
	userHandle []byte, counter uint32) []byte {
	clientData := protocol.CollectedClientData{
		Type:      protocol.AssertCeremony,
		Challenge: challenge,
		Origin:    origin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatal(err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := append([]byte{}, rpIDHash[:]...)
	authData = append(authData, byte(protocol.FlagUserPresent))
	authData = binary.BigEndian.AppendUint32(authData, counter)

	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData := append(append([]byte{}, authData...), clientDataHash[:]...)
	signedHash := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	response := map[string]interface{}{
		"id":    b64(credentialID),
		"rawId": b64(credentialID),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientDataJSON),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        b64(userHandle),
		},
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestWebAuthnAuthFinish(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.localAuthData = make(map[string]localUserData)

	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypeU2F)

	state.signerPublicKeyToKeymasterKeys()

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
	state.HostIdentity = "testHost.example.com"
	logger = state.logger

	u2fAppID = "https://" + state.HostIdentity // this should include the port...but not needed for this test as we assume 443
	state.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Keymaster Server", // Display Name for your site
		RPID:          state.HostIdentity, // Generally the domain name for your site
		RPOrigins:     []string{u2fAppID}, // The origin URL for WebAuthn requests
	})
	if err != nil {
		t.Fatal(err)
	}

	// add a valid webauthn credential to the user profile
	username := "username"
	profile := &userProfile{
		WebauthnData: make(map[int64]*webauthAuthData),
		U2fAuthData:  make(map[int64]*u2fAuthData),
	}
	profile.FixupCredential(username, username)
	privKey, credential := makeTestWebauthnCredential(t)
	err = profile.AddWebAuthnCredential(credential)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SaveUserProfile(username, profile); err != nil {
		t.Fatal(err)
	}

	// The credential must NOT be treated as u2f, so that
	// webauthnAuthFinish takes the ValidateLogin path.
	loadedProfile, _, _, err := state.LoadUserProfile(username)
	if err != nil {
		t.Fatal(err)
	}
	storedCreds := loadedProfile.WebAuthnCredentials()
	if len(storedCreds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(storedCreds))
	}
	if storedCreds[0].AttestationType == "fido-u2f" {
		t.Fatalf("credential must not be fido-u2f")
	}

	// create and store the login session (as webauthnAuthLogin does)
	_, sessionData, err := state.webAuthn.BeginLogin(loadedProfile,
		webauthn.WithAssertionExtensions(webauthn.WithExtensionAppID(u2fAppID)))
	if err != nil {
		t.Fatal(err)
	}
	state.localAuthData[username] = localUserData{
		WebAuthnChallenge: sessionData,
		ExpiresAt:         time.Now().Add(maxAgeU2FVerifySeconds * time.Second),
	}
	// end of setup

	cookieVal, err := state.setNewAuthCookie(nil, username, AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}

	// A response signed by a different key must fail
	badKey, _ := makeTestWebauthnCredential(t)
	badBody := makeTestAssertionResponse(t, badKey, credential.ID,
		sessionData.Challenge, state.HostIdentity, u2fAppID,
		loadedProfile.WebAuthnID(), 1)
	req, err := http.NewRequest("POST", webAuthnAuthFinishPath, bytes.NewReader(badBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(req, state.webauthnAuthFinish, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}

	// A properly signed response must succeed
	body := makeTestAssertionResponse(t, privKey, credential.ID,
		sessionData.Challenge, state.HostIdentity, u2fAppID,
		loadedProfile.WebAuthnID(), 1)
	req, err = http.NewRequest("POST", webAuthnAuthFinishPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&authCookie)
	rr, err := checkRequestHandlerCode(req, state.webauthnAuthFinish, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("authFinish response=%s", rr.Body.String())

	// session must be consumed
	if _, ok := state.localAuthData[username]; ok {
		t.Fatalf("session data was not removed after successful login")
	}
	// auth cookie must now be upgraded
	var upgraded bool
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authInfo, err := state.getAuthInfoFromAuthJWT(cookie.Value)
		if err != nil {
			t.Fatal(err)
		}
		if authInfo.AuthType&AuthTypeFIDO2 == 0 {
			t.Fatalf("auth cookie not upgraded to FIDO2, authType=%d", authInfo.AuthType)
		}
		upgraded = true
	}
	if !upgraded {
		t.Fatalf("no updated auth cookie in response")
	}

	state.dbDone <- struct{}{}
}
