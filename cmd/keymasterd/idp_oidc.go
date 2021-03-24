package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/authutil"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/mendsley/gojwk"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

//For minimal openid connect interaface and easy config we need 5 enpoints
// 1. Discovery Document -> so that consumers need only 3 conf values
// 2. jwks_uri -> where the keys to decrypt document can be found
// 3. authorization_endpoint - > OAUth2 authorization endpoint
// 4. token_endpoint
// 5. userinfo endpoint.

const idpOpenIDCConfigurationDocumentPath = "/.well-known/openid-configuration"
const idpOpenIDCJWKSPath = "/idp/oauth2/jwks"
const idpOpenIDCAuthorizationPath = "/idp/oauth2/authorize"
const idpOpenIDCTokenPath = "/idp/oauth2/token"
const idpOpenIDCUserinfoPath = "/idp/oauth2/userinfo"

// From: https://openid.net/specs/openid-connect-discovery-1_0.html
// We only put required OR implemented fields here
type openIDProviderMetadata struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndoint           string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	JWKSURI                string   `json:"jwks_uri"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	SubjectTypesSupported  []string `json:"subject_types_supported"`
	IDTokenSigningAlgValue []string `json:"id_token_signing_alg_values_supported"`
}

func (state *RuntimeState) idpOpenIDCDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	issuer := state.idpGetIssuer()
	metadata := openIDProviderMetadata{
		Issuer:                 issuer,
		AuthorizationEndpoint:  issuer + idpOpenIDCAuthorizationPath,
		TokenEndoint:           issuer + idpOpenIDCTokenPath,
		UserInfoEndpoint:       issuer + idpOpenIDCUserinfoPath,
		JWKSURI:                issuer + idpOpenIDCJWKSPath,
		ResponseTypesSupported: []string{"code"},               // We only support authorization code flow
		SubjectTypesSupported:  []string{"pairwise", "public"}, // WHAT is THIS?
		IDTokenSigningAlgValue: []string{"RS256"}}
	// need to agree on what scopes we will support

	b, err := json.Marshal(metadata)
	if err != nil {
		log.Printf("Error marshalling in idpOpenIDCDiscoveryHandler: %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Internal Error")
		return
	}

	var out bytes.Buffer
	json.Indent(&out, b, "", "\t")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	out.WriteTo(w)
}

type jwsKeyList struct {
	Keys []*gojwk.Key `json:"keys"`
}

// Need to improve this to account for adding the other signers here.
func (state *RuntimeState) idpOpenIDCJWKSHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	var currentKeys jwsKeyList
	for _, key := range state.KeymasterPublicKeys {
		jwkKey, err := gojwk.PublicKey(key)
		if err != nil {
			log.Printf("error getting key idpOpenIDCJWKSHandler: %s", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "Internal Error")
			return
		}
		jwkKey.Kid, err = getKeyFingerprint(key)
		if err != nil {
			log.Printf("error computing key fingerprint in  idpOpenIDCJWKSHandler: %s", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "Internal Error")
			return
		}
		currentKeys.Keys = append(currentKeys.Keys, jwkKey)
	}
	b, err := json.Marshal(currentKeys)
	if err != nil {
		log.Printf("idpOpenIDCJWKSHandler marshaling error: %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Internal Error")
		return
	}

	var out bytes.Buffer
	json.Indent(&out, b, "", "\t")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	out.WriteTo(w)
}

type keymasterdIDPCodeProtectedData struct {
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

type keymasterdCodeToken struct {
	Issuer        string `json:"iss"` //keymasterd
	Subject       string `json:"sub"` //clientID
	IssuedAt      int64  `json:"iat"`
	Expiration    int64  `json:"exp"`
	Username      string `json:"username"`
	AuthLevel     int64  `json:"auth_level"`
	Nonce         string `json:"nonce,omitEmpty"`
	RedirectURI   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
	Type          string `json:"type"`
	JWTId         string `json:"jti,omitEmpty"`
	DataKeyID     string `json:"data_key_id,omitempty"`
	ProtectedData string `json:"protected_data,omitempty"`
}

func (state *RuntimeState) idpOpenIDCClientCanRedirect(client_id string, redirect_url string) (bool, error) {
	for _, client := range state.Config.OpenIDConnectIDP.Client {
		if client.ClientID != client_id {
			continue
		}
		if len(client.AllowedRedirectDomains) < 1 && len(client.AllowedRedirectURLRE) < 1 {
			return false, nil
		}
		matchedRE := false
		for _, re := range client.AllowedRedirectURLRE {
			matched, err := regexp.MatchString(re, redirect_url)
			if err != nil {
				return false, err
			}
			if matched {
				matchedRE = true
				break
			}
		}
		// if no domains, the matchedRE answer is authoritative, no need to parse
		if len(client.AllowedRedirectDomains) < 1 {
			return matchedRE, nil
		}
		if len(client.AllowedRedirectURLRE) < 1 {
			matchedRE = true
		}
		parsedURL, err := url.Parse(redirect_url)
		if err != nil {
			logger.Debugf(1, "user passed unparsable url as string err = %s", err)
			return false, nil
		}
		if parsedURL.Scheme != "https" {
			return false, nil
		}
		matchedDomain := false
		for _, domain := range client.AllowedRedirectDomains {
			matched := strings.HasSuffix(parsedURL.Hostname(), domain)
			if matched {
				matchedDomain = true
				break
			}
		}
		return matchedDomain && matchedRE, nil
	}
	return false, nil
}

func (state *RuntimeState) idpOpenIDCIsCorsOriginAllowed(origin string, clientId string) (bool, error) {
	parsedURL, err := url.Parse(origin)
	if err != nil {
		logger.Debugf(1, "user passed unparsable url as string err = %s", err)
		return false, nil
	}
	if parsedURL.Scheme != "https" {
		return false, nil
	}

	for _, client := range state.Config.OpenIDConnectIDP.Client {
		if clientId != "" && client.ClientID != clientId {
			continue
		}
		for _, domain := range client.AllowedRedirectDomains {
			matched := strings.HasSuffix(parsedURL.Hostname(), domain)
			if matched {
				return true, nil
			}
		}
	}
	return false, nil
}

const PKCESecretClientDataType = 2
const PKCESecretExpirationSeconds = 18 * 3600

func genRandomBytes() ([]byte, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return nil, err
	}
	return rb, nil
}

type EncodedBackendPKCEKeys struct {
	Base64Keys []string
}

func (keyset *EncodedBackendPKCEKeys) DecodeIntoArray() ([][]byte, error) {
	var result [][]byte
	for _, base64key := range keyset.Base64Keys {

		key, err := base64.URLEncoding.DecodeString(base64key)
		if err != nil {
			return nil, err
		}
		result = append(result, key)
	}
	return result, nil
}
func (keyset *EncodedBackendPKCEKeys) EncodefromArray(inKeys [][]byte) error {
	for _, key := range inKeys {
		base64Key := base64.URLEncoding.EncodeToString(key)
		keyset.Base64Keys = append(keyset.Base64Keys, base64Key)
	}
	return nil
}

func (state *RuntimeState) deserializeKeysetIntoPlaintextKeys(serializedKeySet string) ([][]byte, error) {
	var encodedKeySet EncodedBackendPKCEKeys
	err := json.Unmarshal([]byte(serializedKeySet), &encodedKeySet)
	if err != nil {
		return nil, err
	}
	encryptedKeys, err := encodedKeySet.DecodeIntoArray()
	if err != nil {
		return nil, err
	}
	key, err := state.decryptWithPublicKeys(encryptedKeys)
	if err != nil {
		//probably at this stage, regenerate?
		return nil, err
	}
	var result [][]byte
	result = append(result, key)
	return result, nil
}

// TODO: before making it a feature we must agree on these, for stage 1 is only
func (state *RuntimeState) idpOpenIDCGetClientEncryptionKeys(clientId string, authUser string) ([][]byte, error) {
	clientFound := false
	var client OpenIDConnectClientConfig
	for _, client = range state.Config.OpenIDConnectIDP.Client {
		if client.ClientID == clientId {
			clientFound = true
			break
		}
	}
	if !clientFound {
		return nil, fmt.Errorf("client not found")
	}
	var result [][]byte
	//fetch from DB.. if none create them

	// This is argumentable... shouldbe authUser?
	dbStringIndex := clientId

	ok, keyJSON, err := state.GetSigned(dbStringIndex, PKCESecretClientDataType)
	if err != nil {
		return nil, err
	}

	var encodedKeySet EncodedBackendPKCEKeys
	if ok {
		return state.deserializeKeysetIntoPlaintextKeys(keyJSON)
	}
	// it does not exist we need to create our own... we will ignore the race condition of set/get for now

	//write our own!
	key, err := genRandomBytes()
	if err != nil {
		return nil, err
	}
	encryptedKeys, err := state.encryptWithPublicKeys(key)
	if err != nil {
		return nil, err
	}
	err = encodedKeySet.EncodefromArray(encryptedKeys)
	if err != nil {
		return nil, err
	}
	serializedKeySet, err := json.Marshal(encodedKeySet)
	if err != nil {
		return nil, err
	}

	err = state.UpsertSigned(dbStringIndex, PKCESecretClientDataType, time.Now().Unix()+PKCESecretExpirationSeconds, string(serializedKeySet))
	if err != nil {
		return nil, err
	}
	// it would be better to go to the DB and get the latest one there... since we know know that there is one
	result = append(result, key)

	return result, nil

}

func sealEncodeData(plaintext, nonce, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	trimmedNonce := nonce[:aesgcm.NonceSize()]
	ciphertext := aesgcm.Seal(nil, trimmedNonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func decodeOpenData(cipherText string, nonce, key []byte) ([]byte, error) {
	var err error
	decodedCipherText, err := base64.RawURLEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	trimmedNonce := nonce[:aesgcm.NonceSize()]
	return aesgcm.Open(nil, trimmedNonce, decodedCipherText, nil)
}

func (state *RuntimeState) idpOpenIDCAuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// We are now at exploration stage... and will require pre-authed clients.
	authUser, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	logger.Debugf(1, "AuthUser of idc auth: %s", authUser)
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	// requst MUST be a GET or POST
	if !(r.Method == "GET" || r.Method == "POST") {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Method for Auth Handler")
		return
	}
	err = r.ParseForm()
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	logger.Debugf(2, "Auth request =%+v", r)
	//logger.Printf("IDC auth from=%v", r.Form)
	if r.Form.Get("response_type") != "code" {
		logger.Debugf(1, "Invalid response_type")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Unsupported or Missing response_type for Auth Handler")
		return
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		logger.Debugf(1, "empty client_id abourting")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Empty cleint_id for Auth Handler")
		return
	}
	scope := r.Form.Get("scope")
	validScope := false
	for _, requestedScope := range strings.Split(scope, " ") {
		if requestedScope == "openid" {
			validScope = true
		}
	}
	if !validScope {

		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid scope value for Auth Handler")
		return
	}

	requestRedirectURLString := r.Form.Get("redirect_uri")

	ok, err := state.idpOpenIDCClientCanRedirect(clientID, requestRedirectURLString)
	if err != nil {
		logger.Printf("%v", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "redirect string not valid or clientID uknown")
		return
	}

	jwtId, err := genRandomString()
	if err != nil {
		logger.Printf("Error getting random string %v", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	var protectedData keymasterdIDPCodeProtectedData
	protectedData.CodeChallenge = r.Form.Get("code_challenge")
	protectedData.CodeChallengeMethod = r.Form.Get("code_challenge_method")
	var protectedCipherText string
	if len(protectedData.CodeChallenge) > 0 {
		if len(protectedData.CodeChallengeMethod) > 0 && protectedData.CodeChallengeMethod != "S256" {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Requested Code Challenge, but challenge method is invalid")
			return
		}
		jsonEncodedData, err := json.Marshal(protectedData)
		if err != nil {
			logger.Printf("Error json encoding data %v", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		keys, err := state.idpOpenIDCGetClientEncryptionKeys(clientID, authUser)
		if err != nil {
			logger.Printf("Error getting random string %v", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		protectedCipherText, err = sealEncodeData([]byte(jsonEncodedData), []byte(jwtId), keys[0])
		if err != nil {
			logger.Printf("Error getting random string %v", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}

	}

	//Dont check for now
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")
	//signerOptions.EmbedJWK = true
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: state.Signer}, signerOptions)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	codeToken := keymasterdCodeToken{Issuer: state.idpGetIssuer(), Subject: clientID, IssuedAt: time.Now().Unix()}
	codeToken.JWTId = jwtId
	codeToken.Scope = scope
	codeToken.Expiration = time.Now().Unix() + maxAgeSecondsAuthCookie
	codeToken.Username = authUser
	codeToken.RedirectURI = requestRedirectURLString
	codeToken.Type = "token_endpoint"
	codeToken.ProtectedData = protectedCipherText
	codeToken.Nonce = r.Form.Get("nonce")
	// Do nonce complexity check
	if len(codeToken.Nonce) < 6 && len(codeToken.Nonce) != 0 {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad Nonce value...not enough entropy")
		return
	}
	logger.Debugf(3, "auth request is valid, now proceeding to generate redirect")

	raw, err := jwt.Signed(signer).Claims(codeToken).CompactSerialize()
	if err != nil {
		panic(err)
	}

	redirectPath := fmt.Sprintf("%s?code=%s&state=%s", requestRedirectURLString, raw, url.QueryEscape(r.Form.Get("state")))
	logger.Debugf(3, "auth request is valid, redirect path=%s", redirectPath)
	logger.Printf("IDP: Successful oauth2 authorization:  user=%s redirect url=%s", authUser, requestRedirectURLString)
	eventNotifier.PublishServiceProviderLoginEvent(requestRedirectURLString, authUser)
	http.Redirect(w, r, redirectPath, 302)
	//logger.Printf("raw jwt =%v", raw)
}

type openIDConnectIDToken struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   []string `json:"aud"`
	Expiration int64    `json:"exp"`
	IssuedAt   int64    `json:"iat"`
	AuthTime   int64    `json:"auth_time,omitempty"` //Time of Auth
	Nonce      string   `json:"nonce,omitempty"`
}

type accessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

type userInfoToken struct {
	Username   string `json:"username"`
	Scope      string `json:"scope"`
	Expiration int64  `json:"exp"`
	Type       string `json:"type"`
}

func (state *RuntimeState) idpOpenIDCValidClientSecret(client_id string, clientSecret string) bool {
	for _, client := range state.Config.OpenIDConnectIDP.Client {
		if client.ClientID != client_id {
			continue
		}
		return clientSecret == client.ClientSecret
	}
	return false
}

func (state *RuntimeState) idpOpenIDCValidCodeVerifier(clientId string, codeVerifier string, codeToken keymasterdCodeToken) bool {
	keySet, err := state.idpOpenIDCGetClientEncryptionKeys(clientId, codeToken.Username)
	if err != nil {
		logger.Printf("idpOpenIDCValidCodeVerifier: Error getting encryption keys %v", err)
		return false
	}
	for _, key := range keySet {
		plainTextJson, err := decodeOpenData(codeToken.ProtectedData, []byte(codeToken.JWTId), key)
		if err != nil {
			continue
		}
		var protectedData keymasterdIDPCodeProtectedData
		err = json.Unmarshal([]byte(plainTextJson), &protectedData)
		if err != nil {
			return false
		}
		state.logger.Debugf(0, "Protected Data Found=%+v", protectedData)
		// https://tools.ietf.org/html/rfc7636 section 4.6
		switch protectedData.CodeChallengeMethod {
		case "", "plain":
			return codeVerifier == protectedData.CodeChallenge
		case "S256":
			// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
			sum := sha256.Sum256([]byte(codeVerifier))
			return base64.RawURLEncoding.EncodeToString(sum[:]) == protectedData.CodeChallenge

		default:
			return false
		}
	}
	logger.Debugf(0, "idpOpenIDCValidCodeVerifier: No valid key found")
	return false
}

func (state *RuntimeState) idpOpenIDCTokenHandler(w http.ResponseWriter, r *http.Request) {

	// MUST be POST https://openid.net/specs/openid-connect-core-1_0.html 3.1.3.1
	if !(r.Method == "POST") {
		logger.Printf("invalid method")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Method for Auth Handler")
		return
	}
	err := r.ParseForm()
	if err != nil {
		logger.Printf("error parsing form")
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		logger.Printf("invalid grant type='%s'", r.Form.Get("grant_type"))
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid grant type")
		return
	}
	requestRedirectURLString := r.Form.Get("redirect_uri")
	if requestRedirectURLString == "" {
		logger.Printf("redirect_uri is empty")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid redirect uri")
		return
	}
	logger.Debugf(1, "token request =%+v", r)
	codeString := r.Form.Get("code")
	if codeString == "" {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "nil code")
		return

	}
	tok, err := jwt.ParseSigned(codeString)
	if err != nil {
		logger.Printf("err=%s", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad code")
		return
	}
	logger.Debugf(2, "token request tok=%+v", tok)
	//out := jwt.Claims{}
	keymasterToken := keymasterdCodeToken{}
	//if err := tok.Claims(state.Signer.Public(), &keymasterToken); err != nil {
	if err := state.JWTClaims(tok, &keymasterToken); err != nil {
		logger.Printf("err=%s", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad code")
		return
	}
	logger.Debugf(3, "idc token handler out=%+v", keymasterToken)

	//now is time to extract the values..

	//formClientID := r.Form.Get("clientID")
	logger.Debugf(2, "%+v", r)

	codeVerifier := r.Form.Get("code_verifier")
	unescapeAuthCredentials := true
	clientID, pass, ok := r.BasicAuth()
	if !ok {
		logger.Debugf(1, "warn: basic auth Missing")
		clientID = r.Form.Get("client_id")
		pass = r.Form.Get("client_secret")
		if len(pass) < 1 && len(codeVerifier) < 1 {
			logger.Printf("Cannot get auth credentials in auth request")
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
			return
		}
		if len(clientID) < 1 {
			// This section is kind of unclear. The original rfc6749 spec
			// Did not had this mandatory, however given the need for password
			// based auth it was prety much mandatory.
			// However... with PKCE  the issue is murkier:
			// not mandatory: login.gov (https://developers.login.gov/oidc/)
			// on-docs: auth0, okta,
			// mandatory: onlogin.com
			// In our implementation we ARE explicitly making it mandatory for
			// the PKCE flow.
			// Thus for clarity we are also explicily sending the error cause to
			// help developers debug and be able to potentially enumerate interoperativity
			// issues
			logger.Printf("Missing client_id in auth request")
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "Missing client_id")
			return
		}
		unescapeAuthCredentials = false
	}
	// https://tools.ietf.org/html/rfc6749#section-2.3.1 says the client id and password
	// are actually url-encoded
	if unescapeAuthCredentials {
		unescapedClientID, err := url.QueryUnescape(clientID)
		if err == nil {
			clientID = unescapedClientID
		}
		unescapedPass, err := url.QueryUnescape(pass)
		if err == nil {
			pass = unescapedPass
		}
	}
	valid := false
	if len(codeVerifier) > 0 {
		valid = state.idpOpenIDCValidCodeVerifier(clientID, codeVerifier, keymasterToken)
	}
	if !valid && len(pass) > 0 {
		valid = state.idpOpenIDCValidClientSecret(clientID, pass)
	}
	if !valid {
		logger.Debugf(0, "Error invalid client secret or code verifier")
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}

	originIsValid, err := state.idpOpenIDCIsCorsOriginAllowed(r.Header.Get("Origin"), clientID)
	if err != nil {
		logger.Printf("Error checking Origin")
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}

	// 1. Ensure authoriation client was issued to the authenticated client
	if clientID != keymasterToken.Subject {
		logger.Debugf(0, "Unmatching token Value")
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}
	// 2. verify authorization code is valid
	// 2.a -> expiration
	if keymasterToken.Expiration < time.Now().Unix() {
		logger.Debugf(0, "Expired Token")
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}
	// verify redirect uri matches the one setup in the original request:
	if keymasterToken.RedirectURI != requestRedirectURLString {
		logger.Debugf(0, "Invalid Redirect Target")
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}
	// Verify that the Authorization Code used was issued in response to an OpenID Connect Authentication Request
	if keymasterToken.Type != "token_endpoint" {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}

	signerOptions := (&jose.SignerOptions{}).WithType("JWT")
	kid, err := getKeyFingerprint(state.Signer.Public())
	if err != nil {
		log.Printf("error getting key fingerprint in idpOpenIDCTokenHandler: %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Internal Error")
		return
	}

	signerOptions = signerOptions.WithHeader("kid", kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: state.Signer}, signerOptions)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}

	idToken := openIDConnectIDToken{Issuer: state.idpGetIssuer(), Subject: keymasterToken.Username, Audience: []string{clientID}}
	idToken.Nonce = keymasterToken.Nonce
	idToken.Expiration = keymasterToken.Expiration
	idToken.IssuedAt = time.Now().Unix()

	signedIdToken, err := jwt.Signed(signer).Claims(idToken).CompactSerialize()
	if err != nil {
		panic(err)
	}
	logger.Debugf(2, "raw=%s", signedIdToken)

	userinfoToken := userInfoToken{Username: keymasterToken.Username, Scope: keymasterToken.Scope}
	userinfoToken.Expiration = idToken.Expiration
	userinfoToken.Type = "bearer"
	signedAccessToken, err := jwt.Signed(signer).Claims(userinfoToken).CompactSerialize()
	if err != nil {
		panic(err)
	}

	// The access token will be yet another jwt.
	outToken := accessToken{
		AccessToken: signedAccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(idToken.Expiration - idToken.IssuedAt),
		IDToken:     signedIdToken}

	// and write the json output
	b, err := json.Marshal(outToken)
	if err != nil {
		log.Printf("error marshaling in idpOpenIDCTokenHandler: %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Internal Error")
		return
	}

	var out bytes.Buffer
	json.Indent(&out, b, "", "\t")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if originIsValid {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	}
	out.WriteTo(w)

}

func (state *RuntimeState) getGitDbUserAttributes(username string,
	attributes []string) (bool, map[string][]string, error) {
	if state.gitDB == nil {
		return false, nil, nil
	}
	groups, err := state.gitDB.GetUserGroups(username)
	if err != nil {
		return true, nil, err
	}
	return true, map[string][]string{"groups": prependGroups(
			groups, state.Config.UserInfo.GitDB.GroupPrepend)},
		nil
}

func (state *RuntimeState) getLdapUserAttributes(username string,
	attributes []string) (bool, map[string][]string, error) {
	ldapConfig := state.Config.UserInfo.Ldap
	if ldapConfig.LDAPTargetURLs == "" {
		return false, nil, nil
	}
	var timeoutSecs uint
	timeoutSecs = 2
	for _, ldapUrl := range strings.Split(ldapConfig.LDAPTargetURLs, ",") {
		if len(ldapUrl) < 1 {
			continue
		}
		u, err := authutil.ParseLDAPURL(ldapUrl)
		if err != nil {
			logger.Printf("Failed to parse ldapurl '%s'", ldapUrl)
			continue
		}
		attributeMap, err := authutil.GetLDAPUserAttributes(*u,
			ldapConfig.BindUsername, ldapConfig.BindPassword,
			timeoutSecs, nil, username,
			ldapConfig.UserSearchBaseDNs, ldapConfig.UserSearchFilter,
			attributes)
		if err != nil {
			continue
		}
		userGroups, err := authutil.GetLDAPUserGroups(*u,
			ldapConfig.BindUsername, ldapConfig.BindPassword,
			timeoutSecs, nil, username,
			ldapConfig.UserSearchBaseDNs, ldapConfig.UserSearchFilter,
			ldapConfig.GroupSearchBaseDNs, ldapConfig.GroupSearchFilter)
		if err != nil {
			// TODO: We actually need to check the error, right now we are
			// assuming the user does not exists and go with that.
			logger.Printf("Failed get userGroups for user '%s'", username)
		} else {
			logger.Debugf(1, "Got groups for username %s: %s",
				username, userGroups)
			attributeMap["groups"] = userGroups
		}
		return true, attributeMap, nil
	}
	return true, nil, errors.New("error getting the groups")
}

func (state *RuntimeState) getUserAttributes(username string,
	attributes []string) (map[string][]string, error) {
	ok, attrs, err := state.getLdapUserAttributes(username, attributes)
	if ok {
		return attrs, err
	}
	ok, attrs, err = state.getGitDbUserAttributes(username, attributes)
	if ok {
		return attrs, err
	}
	return nil, nil
}

type openidConnectUserInfo struct {
	Subject           string   `json:"sub"`
	Name              string   `json:"name"`
	Login             string   `json:"login,omitempty"`
	Username          string   `json:"username,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Email             string   `json:"email,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

func (state *RuntimeState) idpOpenIDCUserinfoHandler(w http.ResponseWriter,
	r *http.Request) {
	if !(r.Method == "GET" || r.Method == "POST" || r.Method == "OPTIONS") {
		logger.Printf("Invalid Method for Userinfo Handler")
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Invalid Method for Userinfo Handler")
		return
	}
	logger.Debugf(2, "userinfo request=%+v", r)

	if r.Method == "OPTIONS" {
		origin := r.Header.Get("Origin")
		if origin == "" {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Options MUST contain origin")
		}
		originIsValid, err := state.idpOpenIDCIsCorsOriginAllowed(origin, "")
		if err != nil {
			logger.Printf("Error checking Origin")
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		if originIsValid {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization")

		return

	}

	var accessToken string
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		logger.Debugf(2, "AuthHeader= %s", authHeader)
		splitHeader := strings.Split(authHeader, " ")
		if len(splitHeader) == 2 {
			if splitHeader[0] == "Bearer" {
				accessToken = splitHeader[1]
			}
		}
	}
	if accessToken == "" {
		err := r.ParseForm()
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		accessToken = r.Form.Get("access_token")
	}
	logger.Debugf(1, "access_token='%s'", accessToken)
	if accessToken == "" {
		logger.Printf("access_token='%s'", accessToken)
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Missing access token")
		return
	}
	tok, err := jwt.ParseSigned(accessToken)
	if err != nil {
		logger.Printf("err=%s", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"bad access token")
		return
	}
	logger.Debugf(1, "tok=%+v", tok)
	parsedAccessToken := userInfoToken{}
	if err := state.JWTClaims(tok, &parsedAccessToken); err != nil {
		logger.Printf("err=%s", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad code")
		return
	}
	logger.Debugf(1, "out=%+v", parsedAccessToken)
	// Now we check for validity.
	if parsedAccessToken.Expiration < time.Now().Unix() {
		logger.Printf("expired token attempted to be used for bearer")
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}
	if parsedAccessToken.Type != "bearer" {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}
	// Get email from LDAP if available.
	defaultEmailDomain := state.HostIdentity
	if len(state.Config.OpenIDConnectIDP.DefaultEmailDomain) > 3 {
		defaultEmailDomain = state.Config.OpenIDConnectIDP.DefaultEmailDomain
	}
	email := fmt.Sprintf("%s@%s", parsedAccessToken.Username,
		defaultEmailDomain)
	userAttributeMap, err := state.getUserAttributes(parsedAccessToken.Username,
		[]string{"mail"})
	if err != nil {
		logger.Printf("warn: failed to get user attributes for %s, %s",
			parsedAccessToken.Username, err)
	}
	var userGroups []string
	if userAttributeMap != nil {
		logger.Debugf(2, "useMa=%+v", userAttributeMap)
		mailList, ok := userAttributeMap["mail"]
		if ok {
			email = mailList[0]
		}
		groupList, ok := userAttributeMap["groups"]
		if ok {
			userGroups = groupList
		}
	}
	userInfo := openidConnectUserInfo{
		Subject:  parsedAccessToken.Username,
		Username: parsedAccessToken.Username,
		Email:    email,
		Name:     parsedAccessToken.Username,
		Login:    parsedAccessToken.Username,
		Groups:   userGroups,
	}
	// Write the json output.
	b, err := json.Marshal(userInfo)
	if err != nil {
		log.Printf("error marshaling in idpOpenIDUserinfonHandler: %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"Internal Error")
		return
	}
	logger.Debugf(1, "userinfo=%+v\n b=%s", userInfo, b)
	var out bytes.Buffer
	json.Indent(&out, b, "", "\t")
	w.Header().Set("Content-Type", "application/json")
	out.WriteTo(w)
	logger.Printf("200 Successful userinfo request")
	logger.Debugf(0, " Userinfo response =  %s", b)
}
