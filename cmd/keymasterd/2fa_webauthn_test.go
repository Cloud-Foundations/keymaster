package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/cviecco/webauthn-mds/fido"
	"github.com/stretchr/testify/require"
	"github.com/tstranex/u2f"

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

	state.localAuthData = make(map[localDataKey]localUserData)

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
	// CLI clients use the appid as clientData origin, it must always be sent.
	if appID := compatClient.Response.Extensions["appid"]; appID != u2fAppID {
		t.Fatalf("appid=%v, want %s", appID, u2fAppID)
	}

	state.dbDone <- struct{}{}
}

// The next sections were added via Claude code (Opus 5.5)
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

	state.localAuthData = make(map[localDataKey]localUserData)

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
	state.localAuthData[localDataKey{username: username, dataType: localAuthTypeWebAuthLogin}] = localUserData{
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
	if _, ok := state.localAuthData[localDataKey{username: username, dataType: localAuthTypeWebAuthLogin}]; ok {
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

// newWebAuthnLoginTestState returns a RuntimeState ready for webauthn login
// tests; the caller must run the returned cleanup function.
func newWebAuthnLoginTestState(t *testing.T) (*RuntimeState, func()) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	state.localAuthData = make(map[localDataKey]localUserData)
	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypeU2F)
	state.signerPublicKeyToKeymasterKeys()
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	state.Config.Base.DataDirectory = dir
	if err := initDB(state); err != nil {
		t.Fatal(err)
	}
	state.HostIdentity = "testHost.example.com"
	logger = state.logger
	u2fAppID = "https://" + state.HostIdentity
	state.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Keymaster Server",
		RPID:          state.HostIdentity,
		RPOrigins:     []string{u2fAppID},
	})
	if err != nil {
		t.Fatal(err)
	}
	return state, func() {
		state.dbDone <- struct{}{}
		os.RemoveAll(dir)
		os.Remove(passwdFile.Name())
	}
}

// TestWebAuthnLoginCLIOrigin runs AuthBegin/AuthFinish with clientData built
// the way CLI clients (1.17.0 onward) do: origin is the appid from AuthBegin.
func TestWebAuthnLoginCLIOrigin(t *testing.T) {
	state, cleanup := newWebAuthnLoginTestState(t)
	defer cleanup()

	username := "username"
	profile := &userProfile{
		WebauthnData: make(map[int64]*webauthAuthData),
		U2fAuthData:  make(map[int64]*u2fAuthData),
	}
	profile.FixupCredential(username, username)
	privKey, credential := makeTestWebauthnCredential(t)
	if err := profile.AddWebAuthnCredential(credential); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveUserProfile(username, profile); err != nil {
		t.Fatal(err)
	}
	cookieVal, err := state.setNewAuthCookie(nil, username, AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}

	req, err := http.NewRequest("GET", webAuthnAuthBeginPath+username, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&authCookie)
	rr, err := checkRequestHandlerCode(req, state.webauthnAuthLogin, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	var assertion oldproto.CredentialAssertion
	if err := json.Unmarshal(rr.Body.Bytes(), &assertion); err != nil {
		t.Fatal(err)
	}
	origin, ok := assertion.Response.Extensions["appid"].(string)
	if !ok {
		t.Fatalf("no appid in AuthBegin response: %s", rr.Body.String())
	}

	body := makeTestAssertionResponse(t, privKey, credential.ID,
		assertion.Response.Challenge.String(), assertion.Response.RelyingPartyID,
		origin, profile.WebAuthnID(), 1)
	req, err = http.NewRequest("POST", webAuthnAuthFinishPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&authCookie)
	if _, err := checkRequestHandlerCode(req, state.webauthnAuthFinish, http.StatusOK); err != nil {
		t.Fatal(err)
	}
}

// TestWebAuthnU2FCredentialKeepsAppID checks that U2F registered credentials
// are flagged so go-webauthn keeps the appid extension (needed by browsers).
func TestWebAuthnU2FCredentialKeepsAppID(t *testing.T) {
	state, cleanup := newWebAuthnLoginTestState(t)
	defer cleanup()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := &userProfile{
		WebauthnData: make(map[int64]*webauthAuthData),
		U2fAuthData: map[int64]*u2fAuthData{
			1: {
				Enabled: true,
				Registration: &u2f.Registration{
					KeyHandle: []byte{0x01, 0x02, 0x03, 0x04},
					PubKey:    privKey.PublicKey,
				},
			},
		},
	}
	profile.FixupCredential("username", "username")

	creds := profile.WebAuthnCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].AttestationType != "fido-u2f" || creds[0].AttestationFormat != "fido-u2f" {
		t.Fatalf("type=%q format=%q, want fido-u2f for both",
			creds[0].AttestationType, creds[0].AttestationFormat)
	}

	options, sessionData, err := state.webAuthn.BeginLogin(profile,
		webauthn.WithAssertionExtensions(webauthn.WithExtensionAppID(u2fAppID)))
	if err != nil {
		t.Fatal(err)
	}
	if options.Response.Extensions.AppID != u2fAppID {
		t.Fatalf("options appid=%q, want %s", options.Response.Extensions.AppID, u2fAppID)
	}
	if sessionData.Extensions.AppID != u2fAppID {
		t.Fatalf("session appid=%q, want %s", sessionData.Extensions.AppID, u2fAppID)
	}
}

// This test is only run to create a new saved profile/key
func TestSaveCredentialsToFile(t *testing.T) {
	destPrefix := os.Getenv("TESTCREDPREFIX")
	if destPrefix == "" {
		t.Skip()
	}
	// add a valid webauthn credential to the user profile
	username := "username"
	profile := &userProfile{
		WebauthnData: make(map[int64]*webauthAuthData),
		U2fAuthData:  make(map[int64]*u2fAuthData),
	}
	profile.FixupCredential(username, username)
	privKey, credential := makeTestWebauthnCredential(t)
	err := profile.AddWebAuthnCredential(credential)
	require.NoError(t, err)

	serializedProfile, err := profile.Serialize()
	require.NoError(t, err)
	profileFilename := destPrefix + ".profile"
	t.Logf("desPrefix=%s", destPrefix)
	err = os.WriteFile(profileFilename, serializedProfile, 0644)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	keyFilename := destPrefix + ".key.pem"
	err = os.WriteFile(keyFilename, pemBytes, 0644)
	require.NoError(t, err)
}

func TestWebauthnAuthenticateWithSavedProfiles(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	require.NoError(t, err)

	defer os.Remove(passwdFile.Name()) // clean up

	state.localAuthData = make(map[localDataKey]localUserData)

	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypeU2F)

	state.signerPublicKeyToKeymasterKeys()

	dir, err := os.MkdirTemp("", "example")
	require.NoError(t, err)

	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	err = initDB(state)
	require.NoError(t, err)

	state.HostIdentity = "testHost.example.com"
	logger = state.logger

	u2fAppID = "https://" + state.HostIdentity // this should include the port...but not needed for this test as we assume 443
	state.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Keymaster Server", // Display Name for your site
		RPID:          state.HostIdentity, // Generally the domain name for your site
		RPOrigins:     []string{u2fAppID}, // The origin URL for WebAuthn requests
	})
	require.NoError(t, err)

	username := "username"
	profilePrefixes := []string{"testdata/webauth-0.16"}
	for _, prefix := range profilePrefixes {
		profilefilename := prefix + ".profile"
		keyFilename := prefix + ".key.pem"
		profileBytes, err := os.ReadFile(profilefilename)
		require.NoError(t, err)
		profile, err := DeserializeProfile(profileBytes)
		require.NoError(t, err)

		pemBytes, err := os.ReadFile(keyFilename)
		require.NoError(t, err)
		block, _ := pem.Decode(pemBytes)
		require.NotNil(t, block)
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)

		privKey, ok := parsedKey.(*ecdsa.PrivateKey)
		require.True(t, ok)

		webauthCreds := profile.WebAuthnCredentials()
		require.Len(t, webauthCreds, 1)
		credential := webauthCreds[0]

		err = state.SaveUserProfile(username, profile)
		require.NoError(t, err)

		// create and store the login session (as webauthnAuthLogin does)
		_, sessionData, err := state.webAuthn.BeginLogin(profile,
			webauthn.WithAssertionExtensions(webauthn.WithExtensionAppID(u2fAppID)))
		if err != nil {
			t.Fatal(err)
		}
		state.localAuthData[localDataKey{username: username, dataType: localAuthTypeWebAuthLogin}] = localUserData{
			WebAuthnChallenge: sessionData,
			ExpiresAt:         time.Now().Add(maxAgeU2FVerifySeconds * time.Second),
		}
		// end of setup

		cookieVal, err := state.setNewAuthCookie(nil, username, AuthTypePassword)
		if err != nil {
			t.Fatal(err)
		}
		authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}

		// A properly signed response must succeed
		body := makeTestAssertionResponse(t, privKey, credential.ID,
			sessionData.Challenge, state.HostIdentity, u2fAppID,
			profile.WebAuthnID(), 1)
		req, err := http.NewRequest("POST", webAuthnAuthFinishPath, bytes.NewReader(body))
		require.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&authCookie)
		rr, err := checkRequestHandlerCode(req, state.webauthnAuthFinish, http.StatusOK)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("authFinish response=%s", rr.Body.String())

	}
	state.dbDone <- struct{}{}
}

// NOTE: Tests for registration where done via Claude (opus 5.5)
// makeTestAttestationResponse builds the JSON body an authenticator/browser
// would POST to finish a webauthn registration for the given challenge.
// It uses the "none" attestation format.
func makeTestAttestationResponse(t *testing.T, credential webauthn.Credential,
	challenge string, rpID string, origin string) []byte {
	clientData := protocol.CollectedClientData{
		Type:      protocol.CreateCeremony,
		Challenge: challenge,
		Origin:    origin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatal(err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := append([]byte{}, rpIDHash[:]...)
	authData = append(authData,
		byte(protocol.FlagUserPresent|protocol.FlagAttestedCredentialData))
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credential.ID)))
	authData = append(authData, credential.ID...)
	authData = append(authData, credential.PublicKey...)

	attestationObject, err := webauthncbor.Marshal(map[string]interface{}{
		"fmt":      "none",
		"attStmt":  map[string]interface{}{},
		"authData": authData,
	})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	response := map[string]interface{}{
		"id":    b64(credential.ID),
		"rawId": b64(credential.ID),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientDataJSON),
			"attestationObject": b64(attestationObject),
		},
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestWebAuthnRegistrationFinish(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.localAuthData = make(map[localDataKey]localUserData)

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
	// end of setup

	username := "username"
	cookieVal, err := state.setNewAuthCookie(nil, username, AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	privKey, credential := makeTestWebauthnCredential(t)

	newFinishRequest := func(user string, body []byte, cookie *http.Cookie) *http.Request {
		req, err := http.NewRequest("POST", webAutnRegististerFinishPath+user,
			bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		return req
	}

	// Finishing without a pending registration must fail
	body := makeTestAttestationResponse(t, credential, "bm9zZXNzaW9u",
		state.HostIdentity, u2fAppID)
	_, err = checkRequestHandlerCode(newFinishRequest(username, body, &authCookie),
		state.webauthnFinishRegistration, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}

	// Begin the registration, this stores the session data
	req, err := http.NewRequest("GET", webAutnRegististerRequestPath+username, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&authCookie)
	regData, err := checkRequestHandlerCode(req, state.webauthnBeginRegistration, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	var options protocol.CredentialCreation
	if err = json.Unmarshal(regData.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	challenge := options.Response.Challenge.String()
	if _, ok := state.localAuthData[localDataKey{username: username, dataType: localAuthTypeWebAuthRegistration}]; !ok {
		t.Fatalf("registration session not stored")
	}

	// A different user (non admin) cannot finish the registration
	otherCookieVal, err := state.setNewAuthCookie(nil, "otheruser", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	otherCookie := http.Cookie{Name: authCookieName, Value: otherCookieVal}
	body = makeTestAttestationResponse(t, credential, challenge,
		state.HostIdentity, u2fAppID)
	_, err = checkRequestHandlerCode(newFinishRequest(username, body, &otherCookie),
		state.webauthnFinishRegistration, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}

	// A response for the wrong challenge must fail
	body = makeTestAttestationResponse(t, credential, "d3JvbmdjaGFsbGVuZ2U",
		state.HostIdentity, u2fAppID)
	_, err = checkRequestHandlerCode(newFinishRequest(username, body, &authCookie),
		state.webauthnFinishRegistration, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}

	// A response for the wrong origin must fail
	body = makeTestAttestationResponse(t, credential, challenge,
		state.HostIdentity, "https://evil.example.com")
	_, err = checkRequestHandlerCode(newFinishRequest(username, body, &authCookie),
		state.webauthnFinishRegistration, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}

	// A valid response must succeed
	body = makeTestAttestationResponse(t, credential, challenge,
		state.HostIdentity, u2fAppID)
	rr, err := checkRequestHandlerCode(newFinishRequest(username, body, &authCookie),
		state.webauthnFinishRegistration, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("registerFinish response=%s", rr.Body.String())

	// session must be consumed
	if _, ok := state.localAuthData[localDataKey{username: username, dataType: localAuthTypeWebAuthRegistration}]; ok {
		t.Fatalf("session data was not removed after successful registration")
	}

	// The credential must be stored in the profile
	profile, ok, _, err := state.LoadUserProfile(username)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("profile for %s not found", username)
	}
	if len(profile.WebauthnData) != 1 {
		t.Fatalf("expected 1 webauthn registration, got %d", len(profile.WebauthnData))
	}
	storedCreds := profile.WebAuthnCredentials()
	if len(storedCreds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(storedCreds))
	}
	if !bytes.Equal(storedCreds[0].ID, credential.ID) {
		t.Fatalf("stored credential ID mismatch")
	}
	if !bytes.Equal(storedCreds[0].PublicKey, credential.PublicKey) {
		t.Fatalf("stored credential public key mismatch")
	}
	if storedCreds[0].AttestationFormat != "none" {
		t.Fatalf("unexpected attestation format %q", storedCreds[0].AttestationFormat)
	}

	// The registered credential must be usable for login
	_, sessionData, err := state.webAuthn.BeginLogin(profile)
	if err != nil {
		t.Fatal(err)
	}
	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(
		makeTestAssertionResponse(t, privKey, credential.ID,
			sessionData.Challenge, state.HostIdentity, u2fAppID,
			profile.WebAuthnID(), 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = state.webAuthn.ValidateLogin(profile, *sessionData, parsedResponse); err != nil {
		t.Fatalf("login with registered credential failed: %s", err)
	}

	state.dbDone <- struct{}{}
}

func makeTestX5CCert(t *testing.T, subject string, notBefore, notAfter time.Time,
	isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (
	*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if parent == nil {
		parent = template
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent,
		&key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestVerifyX5CChain(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(time.Hour)
	root, rootKey := makeTestX5CCert(t, "root", notBefore, notAfter, true, nil, nil)
	leaf, _ := makeTestX5CCert(t, "leaf", notBefore, notAfter, false, root, rootKey)
	otherRoot, _ := makeTestX5CCert(t, "other", notBefore, notAfter, true, nil, nil)
	expiredLeaf, _ := makeTestX5CCert(t, "expired", now.Add(-2*time.Hour),
		now.Add(-time.Hour), false, root, rootKey)

	// Self standing attestation cert (fido-u2f style)
	require.NoError(t, verifyX5CChain([]any{leaf.Raw}, now))
	// Full chain
	require.NoError(t, verifyX5CChain([]any{leaf.Raw, root.Raw}, now))
	// Empty
	require.Error(t, verifyX5CChain([]any{}, now))
	// Not bytes
	require.Error(t, verifyX5CChain([]any{"notbytes"}, now))
	// Garbage
	require.Error(t, verifyX5CChain([]any{[]byte("garbage")}, now))
	// Wrong issuer
	require.Error(t, verifyX5CChain([]any{leaf.Raw, otherRoot.Raw}, now))
	// Expired
	require.Error(t, verifyX5CChain([]any{expiredLeaf.Raw, root.Raw}, now))
	// Not yet valid
	require.Error(t, verifyX5CChain([]any{leaf.Raw, root.Raw}, now.Add(-2*time.Hour)))

	// Attestation statement level checks
	noPolicy := protocol.AttestationPolicy{}
	noSignature := protocol.SignaturePolicy{}
	parsed := &protocol.ParsedCredentialCreationData{}
	cn, validated, err := verifyAttestationX5C(parsed, nil, nil, noPolicy,
		noSignature, now)
	require.NoError(t, err)
	require.False(t, validated)
	require.Equal(t, "", cn)
	// Valid chain, but no metadata so not validated
	parsed.Response.AttestationObject.AttStatement = map[string]any{
		"x5c": []any{leaf.Raw, root.Raw}}
	cn, validated, err = verifyAttestationX5C(parsed, nil, nil, noPolicy,
		noSignature, now)
	require.NoError(t, err)
	require.False(t, validated)
	require.Equal(t, leaf.Subject.CommonName, cn)
	parsed.Response.AttestationObject.AttStatement["x5c"] = "notanarray"
	cn, validated, err = verifyAttestationX5C(parsed, nil, nil, noPolicy,
		noSignature, now)
	require.NoError(t, err)
	require.False(t, validated)
	require.Equal(t, "", cn)
	// Invalid chain still returns the common name
	parsed.Response.AttestationObject.AttStatement = nil
	parsed.Response.AttestationObject.SubStatements = []protocol.NonCompoundAttestationObject{
		{AttStatement: map[string]any{"x5c": []any{leaf.Raw, otherRoot.Raw}}},
	}
	cn, validated, err = verifyAttestationX5C(parsed, nil, nil, noPolicy,
		noSignature, now)
	require.NoError(t, err)
	require.False(t, validated)
	require.Equal(t, leaf.Subject.CommonName, cn)
	// Internal error
	_, _, err = verifyAttestationX5C(nil, nil, nil, noPolicy, noSignature, now)
	require.Error(t, err)
}

// makeTestPackedAttestationResponse builds a credential creation response
// using the "packed" attestation format with an x5c chain made of a
// freshly generated root and attestation certificate.
func makeTestPackedAttestationResponse(t *testing.T, credential webauthn.Credential,
	challenge string, rpID string, origin string) []byte {
	now := time.Now()
	root, rootKey := makeTestX5CCert(t, "root", now.Add(-time.Hour),
		now.Add(time.Hour), true, nil, nil)
	attKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Keymaster Test"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "test attestation",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
	}
	attDer, err := x509.CreateCertificate(rand.Reader, template, root,
		&attKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	clientData := protocol.CollectedClientData{
		Type:      protocol.CreateCeremony,
		Challenge: challenge,
		Origin:    origin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatal(err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := append([]byte{}, rpIDHash[:]...)
	authData = append(authData,
		byte(protocol.FlagUserPresent|protocol.FlagAttestedCredentialData))
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credential.ID)))
	authData = append(authData, credential.ID...)
	authData = append(authData, credential.PublicKey...)

	clientDataHash := sha256.Sum256(clientDataJSON)
	signedHash := sha256.Sum256(append(append([]byte{}, authData...),
		clientDataHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, attKey, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}
	attestationObject, err := webauthncbor.Marshal(map[string]interface{}{
		"fmt": "packed",
		"attStmt": map[string]interface{}{
			"alg": int64(webauthncose.AlgES256),
			"sig": sig,
			"x5c": []interface{}{attDer, root.Raw},
		},
		"authData": authData,
	})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	response := map[string]interface{}{
		"id":    b64(credential.ID),
		"rawId": b64(credential.ID),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientDataJSON),
			"attestationObject": b64(attestationObject),
		},
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestVerifyAttestationX5CWithMetadata(t *testing.T) {
	_, credential := makeTestWebauthnCredential(t)
	body := makeTestPackedAttestationResponse(t, credential, "Y2hhbGxlbmdl",
		"testHost.example.com", "https://testHost.example.com")
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	require.NoError(t, err)
	clientDataHash := sha256.Sum256(parsed.Raw.AttestationResponse.ClientDataJSON)

	// Without metadata the (self consistent) chain is not validated
	cn, validated, err := verifyAttestationX5C(parsed, clientDataHash[:], nil,
		protocol.AttestationPolicy{}, protocol.SignaturePolicy{}, time.Now())
	require.NoError(t, err)
	require.False(t, validated)
	require.Equal(t, "test attestation", cn)

	// The signature is valid, so a metadata failure is due to the
	// authenticator not being known to the FIDO MDS
	require.NoError(t, parsed.Response.AttestationObject.VerifyAttestation(
		clientDataHash[:], nil, protocol.AttestationPolicy{},
		protocol.SignaturePolicy{}))
	mds, err := fido.GetProvider()
	require.NoError(t, err)
	cn, validated, err = verifyAttestationX5C(parsed, clientDataHash[:], mds,
		protocol.AttestationPolicy{}, protocol.SignaturePolicy{}, time.Now())
	require.NoError(t, err)
	require.False(t, validated)
	require.Equal(t, "test attestation", cn)
}
