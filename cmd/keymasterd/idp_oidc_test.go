package main

import (
	"encoding/json"
	stdlog "log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Cloud-Foundations/Dominator/lib/log/debuglogger"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"gopkg.in/square/go-jose.v2/jwt"
)

func init() {
	//logger = stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger = debuglogger.New(slogger)
	/*
		http.HandleFunc("/userinfo", userinfoHandler)
		http.HandleFunc("/token", tokenHandler)
		http.HandleFunc("/", handler)
		logger.Printf("about to start server")
		go http.ListenAndServe(":12345", nil)
		time.Sleep(20 * time.Millisecond)
		_, err := http.Get("http://localhost:12345")
		if err != nil {
			logger.Fatal(err)
		}
	*/
}

func TestIDPOpenIDCMetadataHandler(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.pendingOauth2 = make(map[string]pendingAuth2Request)

	url := idpOpenIDCConfigurationDocumentPath
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.idpOpenIDCDiscoveryHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

func TestIDPOpenIDCJWKSHandler(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.pendingOauth2 = make(map[string]pendingAuth2Request)

	url := idpOpenIDCJWKSPath
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.idpOpenIDCJWKSHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

func TestIDPOpenIDCAuthorizationHandlerSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.pendingOauth2 = make(map[string]pendingAuth2Request)
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}
	state.signerPublicKeyToKeymasterKeys()
	state.HostIdentity = "localhost"

	valid_client_id := "valid_client_id"
	valid_client_secret := "secret_password"
	valid_redirect_uri := "https://localhost:12345"
	clientConfig := OpenIDConnectClientConfig{ClientID: valid_client_id, ClientSecret: valid_client_secret, AllowedRedirectURLRE: []string{"localhost"}}
	state.Config.OpenIDConnectIDP.Client = append(state.Config.OpenIDConnectIDP.Client, clientConfig)

	//url := idpOpenIDCAuthorizationPath
	req, err := http.NewRequest("GET", idpOpenIDCAuthorizationPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	//First we do a simple request.. no auth should fail for now.. after build out it
	// should be a redirect to the login page
	_, err = checkRequestHandlerCode(req, state.idpOpenIDCAuthorizationHandler, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// now we add a cookie for auth
	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)
	// and we retry with no params... it should fail again
	_, err = checkRequestHandlerCode(req, state.idpOpenIDCAuthorizationHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}
	// add the required params
	form := url.Values{}
	form.Add("scope", "openid")
	form.Add("response_type", "code")
	form.Add("client_id", valid_client_id)
	form.Add("redirect_uri", valid_redirect_uri)
	form.Add("nonce", "123456789")
	form.Add("state", "this is my state")

	postReq, err := http.NewRequest("POST", idpOpenIDCAuthorizationPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	postReq.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	postReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	postReq.AddCookie(&authCookie)

	rr, err := checkRequestHandlerCode(postReq, state.idpOpenIDCAuthorizationHandler, http.StatusFound)
	if err != nil {
		t.Logf("bad handler code %+v", rr)
		t.Fatal(err)
	}
	t.Logf("%+v", rr)
	locationText := rr.Header().Get("Location")
	t.Logf("location=%s", locationText)
	location, err := url.Parse(locationText)
	if err != nil {
		t.Fatal(err)
	}
	rCode := location.Query().Get("code")
	t.Logf("rCode=%s", rCode)
	tok, err := jwt.ParseSigned(rCode)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tok=%+v", tok)
	//out := jwt.Claims{}
	out := keymasterdCodeToken{}
	if err := tok.Claims(state.Signer.Public(), &out); err != nil {
		t.Fatal(err)
	}
	t.Logf("out=%+v", out)

	//now we do a token request
	tokenForm := url.Values{}
	tokenForm.Add("grant_type", "authorization_code")
	tokenForm.Add("redirect_uri", valid_redirect_uri)
	tokenForm.Add("code", rCode)

	tokenReq, err := http.NewRequest("POST", idpOpenIDCTokenPath, strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenReq.Header.Add("Content-Length", strconv.Itoa(len(tokenForm.Encode())))
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(valid_client_id, valid_client_secret)
	//idpOpenIDCTokenHandler

	tokenRR, err := checkRequestHandlerCode(tokenReq, state.idpOpenIDCTokenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	resultAccessToken := tokenResponse{}
	body := tokenRR.Result().Body
	err = json.NewDecoder(body).Decode(&resultAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("resultAccessToken='%+v'", resultAccessToken)

	//now the userinfo
	userinfoForm := url.Values{}
	userinfoForm.Add("access_token", resultAccessToken.AccessToken)

	userinfoReq, err := http.NewRequest("POST", idpOpenIDCUserinfoPath, strings.NewReader(userinfoForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	userinfoReq.Header.Add("Content-Length", strconv.Itoa(len(userinfoForm.Encode())))
	userinfoReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, err = checkRequestHandlerCode(userinfoReq, state.idpOpenIDCUserinfoHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

}

func TestIdpOpenIDCClientCanRedirectFilters(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	weakREWithDomains := OpenIDConnectClientConfig{
		ClientID:               "weakREWithDomains",
		AllowedRedirectURLRE:   []string{"https://[^/]*\\.example\\.com"},
		AllowedRedirectDomains: []string{"example.com"},
	}
	state.Config.OpenIDConnectIDP.Client = append(state.Config.OpenIDConnectIDP.Client, weakREWithDomains)
	onlyDomainConfig := OpenIDConnectClientConfig{
		ClientID:               "onlyWithDomains",
		AllowedRedirectDomains: []string{"example.com"},
	}
	state.Config.OpenIDConnectIDP.Client = append(state.Config.OpenIDConnectIDP.Client, onlyDomainConfig)

	attackerTestURLS := []string{
		"https://example.com.evil.com",
		"https://example.com@evil.com",
		"https://evil.com?target=example.com",
		"http://www.example.com",
		"https://http:www.example.com@evil.com",
	}
	expectedSuccessURLS := []string{
		"https://www.example.com",
		"https://other.example.com:443",
	}
	testConfigClients := []string{"weakREWithDomains", "onlyWithDomains"}
	for _, clientID := range testConfigClients {
		client, err := state.idpOpenIDCGetClientConfig(clientID)
		if err != nil {
			t.Fatal(err)
		}
		for _, mustFailURL := range attackerTestURLS {
			resultMatch, err := client.CanRedirectToURL(mustFailURL)
			if err != nil {
				t.Fatal(err)
			}
			if resultMatch == true {
				t.Fatal("should NOT have allowed this url")
			}
		}
		for _, mustPassURL := range expectedSuccessURLS {
			resultMatch, err := client.CanRedirectToURL(mustPassURL)
			if err != nil {
				t.Fatal(err)
			}
			if resultMatch == false {
				t.Fatal("should have allowed this url")
			}
		}
	}
}

func TestIdpSealUnsealRoundTrip(t *testing.T) {
	key, err := genRandomBytes()
	if err != nil {
		t.Fatal(err)
	}
	nonceStr, err := genRandomString()
	if err != nil {
		t.Fatal(err)
	}
	originalPlainText := "hello world"
	nonce := []byte(nonceStr)
	cipherText, err := sealEncodeData([]byte(originalPlainText), nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ciphertext=%s", cipherText)
	plainText, err := decodeOpenData(cipherText, nonce, key)
	plainTextStr := string(plainText)
	if plainTextStr != originalPlainText {
		t.Fatalf("texts do not match original=%s recovered=%s", originalPlainText, plainTextStr)
	}
}

// https://tools.ietf.org/html/rfc7636
// we use a third party code generator to check some of the compatiblity issues
func TestIDPOpenIDCPKCEFlowSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.pendingOauth2 = make(map[string]pendingAuth2Request)
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}
	state.signerPublicKeyToKeymasterKeys()
	state.HostIdentity = "localhost"
	valid_client_id := "valid_client_id"
	valid_redirect_uri := "https://localhost:12345"
	nonPKCEclientID := "nonPKCEClientId"
	clientConfig := OpenIDConnectClientConfig{ClientID: valid_client_id, ClientSecret: "", AllowedRedirectURLRE: []string{"localhost"}}
	clientConfig2 := OpenIDConnectClientConfig{ClientID: nonPKCEclientID, ClientSecret: "supersecret", AllowedRedirectURLRE: []string{"localhost"}}
	state.Config.OpenIDConnectIDP.Client = append(state.Config.OpenIDConnectIDP.Client, clientConfig)
	state.Config.OpenIDConnectIDP.Client = append(state.Config.OpenIDConnectIDP.Client, clientConfig2)
	// now we add a cookie for auth
	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	//prepare code challenge
	var CodeVerifier, _ = cv.CreateCodeVerifier()
	// Create code_challenge with S256 method
	codeChallenge := CodeVerifier.CodeChallengeS256()
	// add the required params
	form := url.Values{}
	form.Add("scope", "openid")
	form.Add("response_type", "code")
	form.Add("client_id", valid_client_id)
	form.Add("redirect_uri", valid_redirect_uri)
	form.Add("nonce", "123456789")
	form.Add("state", "this is my state")
	form.Add("code_challenge_method", "S256")
	form.Add("code_challenge", codeChallenge)
	postReq, err := http.NewRequest("POST", idpOpenIDCAuthorizationPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	postReq.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	postReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&authCookie)
	rr, err := checkRequestHandlerCode(postReq, state.idpOpenIDCAuthorizationHandler, http.StatusFound)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", rr)
	locationText := rr.Header().Get("Location")
	t.Logf("location=%s", locationText)
	location, err := url.Parse(locationText)
	if err != nil {
		t.Fatal(err)
	}
	rCode := location.Query().Get("code")
	t.Logf("rCode=%s", rCode)

	// a broken code verifier should not grant us access:
	badVerifierTokenForm := url.Values{}
	badVerifierTokenForm.Add("grant_type", "authorization_code")
	badVerifierTokenForm.Add("redirect_uri", valid_redirect_uri)
	badVerifierTokenForm.Add("code", rCode)
	badVerifierTokenForm.Add("client_id", valid_client_id)
	badVerifierTokenForm.Add("code_verifier", "invalidValue")
	badVerifierTokenReq, err := http.NewRequest("POST", idpOpenIDCTokenPath, strings.NewReader(badVerifierTokenForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	badVerifierTokenReq.Header.Add("Content-Length", strconv.Itoa(len(badVerifierTokenForm.Encode())))
	badVerifierTokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, err = checkRequestHandlerCode(badVerifierTokenReq, state.idpOpenIDCTokenHandler, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// now a good verifier, but bad client_id
	badVerifierTokenForm.Set("code_verifier", CodeVerifier.String())
	badVerifierTokenForm.Set("client_id", nonPKCEclientID)
	badVerifierTokenReq, err = http.NewRequest("POST", idpOpenIDCTokenPath, strings.NewReader(badVerifierTokenForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	badVerifierTokenReq.Header.Add("Content-Length", strconv.Itoa(len(badVerifierTokenForm.Encode())))
	badVerifierTokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, err = checkRequestHandlerCode(badVerifierTokenReq, state.idpOpenIDCTokenHandler, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	//now we do a valid token request
	tokenForm := url.Values{}
	tokenForm.Add("grant_type", "authorization_code")
	tokenForm.Add("redirect_uri", valid_redirect_uri)
	tokenForm.Add("code", rCode)
	tokenForm.Add("client_id", valid_client_id)
	tokenForm.Add("code_verifier", CodeVerifier.String())
	tokenReq, err := http.NewRequest("POST", idpOpenIDCTokenPath, strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenReq.Header.Add("Content-Length", strconv.Itoa(len(tokenForm.Encode())))
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	tokenRR, err := checkRequestHandlerCode(tokenReq, state.idpOpenIDCTokenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	resultAccessToken := tokenResponse{}
	body := tokenRR.Result().Body
	err = json.NewDecoder(body).Decode(&resultAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("resultAccessToken='%+v'", resultAccessToken)
	//now the userinfo
	userinfoForm := url.Values{}
	userinfoForm.Add("access_token", resultAccessToken.AccessToken)
	userinfoReq, err := http.NewRequest("POST", idpOpenIDCUserinfoPath, strings.NewReader(userinfoForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	userinfoReq.Header.Add("Content-Length", strconv.Itoa(len(userinfoForm.Encode())))
	userinfoReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, err = checkRequestHandlerCode(userinfoReq, state.idpOpenIDCUserinfoHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

// we use a third party code generator to check some of the compatiblity issues
func TestIDPOpenIDCPKCEFlowWithAudienceSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.pendingOauth2 = make(map[string]pendingAuth2Request)
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}
	state.signerPublicKeyToKeymasterKeys()
	state.HostIdentity = "localhost"

	valid_client_id := "valid_client_id"
	//valid_client_secret := "secret_password"
	valid_redirect_uri := "https://localhost:12345"
	clientConfig := OpenIDConnectClientConfig{ClientID: valid_client_id, ClientSecret: "",
		AllowClientChosenAudiences: true,
		AllowedRedirectURLRE:       []string{"localhost"}, AllowedRedirectDomains: []string{"localhost"},
	}
	state.Config.OpenIDConnectIDP.Client = append(state.Config.OpenIDConnectIDP.Client, clientConfig)

	// now we add a cookie for auth
	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}

	//prepare code challenge
	var CodeVerifier, _ = cv.CreateCodeVerifier()

	// Create code_challenge with S256 method
	codeChallenge := CodeVerifier.CodeChallengeS256()

	// add the required params
	form := url.Values{}
	form.Add("scope", "openid")
	form.Add("response_type", "code")
	form.Add("client_id", valid_client_id)
	form.Add("redirect_uri", valid_redirect_uri)
	form.Add("nonce", "123456789")
	form.Add("state", "this is my state")
	form.Add("code_challenge_method", "S256")
	form.Add("code_challenge", codeChallenge)
	form.Add("audience", "https://api.localhost")

	postReq, err := http.NewRequest("POST", idpOpenIDCAuthorizationPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	postReq.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	postReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	postReq.AddCookie(&authCookie)
	rr, err := checkRequestHandlerCode(postReq, state.idpOpenIDCAuthorizationHandler, http.StatusFound)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", rr)
	locationText := rr.Header().Get("Location")
	t.Logf("location=%s", locationText)
	location, err := url.Parse(locationText)
	if err != nil {
		t.Fatal(err)
	}
	rCode := location.Query().Get("code")
	t.Logf("rCode=%s", rCode)

	//now we do a token request
	tokenForm := url.Values{}
	tokenForm.Add("grant_type", "authorization_code")
	tokenForm.Add("redirect_uri", valid_redirect_uri)
	tokenForm.Add("code", rCode)
	tokenForm.Add("client_id", valid_client_id)
	tokenForm.Add("code_verifier", CodeVerifier.String())

	tokenReq, err := http.NewRequest("POST", idpOpenIDCTokenPath, strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenReq.Header.Add("Content-Length", strconv.Itoa(len(tokenForm.Encode())))
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	tokenRR, err := checkRequestHandlerCode(tokenReq, state.idpOpenIDCTokenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	resultAccessToken := tokenResponse{}
	body := tokenRR.Result().Body
	err = json.NewDecoder(body).Decode(&resultAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("resultAccessToken='%+v'", resultAccessToken)

	// lets parse the access token to ensure the requested audience is there.
	tok, err := jwt.ParseSigned(resultAccessToken.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	logger.Debugf(1, "tok=%+v", tok)
	parsedAccessToken := bearerAccessToken{}
	if err := state.JWTClaims(tok, &parsedAccessToken); err != nil {
		t.Fatal(err)
	}
	t.Logf("parsedAccessToken Data ='%+v'", parsedAccessToken)
	if len(parsedAccessToken.Audience) != 2 {
		t.Fatalf("should have had only 2 audiences")
	}
	if parsedAccessToken.Audience[0] != "https://api.localhost" {
		t.Fatalf("0th audience is not the one requested")
	}

	//now the userinfo
	userinfoForm := url.Values{}
	userinfoForm.Add("access_token", resultAccessToken.AccessToken)

	userinfoReq, err := http.NewRequest("POST", idpOpenIDCUserinfoPath, strings.NewReader(userinfoForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	userinfoReq.Header.Add("Content-Length", strconv.Itoa(len(userinfoForm.Encode())))
	userinfoReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, err = checkRequestHandlerCode(userinfoReq, state.idpOpenIDCUserinfoHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

}
