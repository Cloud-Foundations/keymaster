package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	// TODO: we should not be using this protocol at all,
	// We need a break scenario to destroy backwards compatibility at
	// the client side.
	"github.com/tstranex/u2f"

	oldproto "github.com/duo-labs/webauthn/protocol"
	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/proto/eventmon"
)

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func webauthnJsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	logger.Debugf(3, "webauth json response=%s", dj)
	fmt.Fprintf(w, "%s", dj)
}

const webAutnRegististerRequestPath = "/webauthn/RegisterRequest/"

// RegisterRequest?
func (state *RuntimeState) webauthnBeginRegistration(w http.ResponseWriter, r *http.Request) {
	state.logger.Debugf(3, "top of webauthnBeginRegistration")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// /u2f/RegisterRequest/<assumed user>
	// pieces[0] == "" pieces[1] = "u2f" pieces[2] == "RegisterRequest"
	pieces := strings.Split(r.URL.Path, "/")

	var assumedUser string
	if len(pieces) >= 4 {
		assumedUser = pieces[3]
	} else {
		state.logger.Debugf(1, "webauthnBeginRegistration: bad number of pieces")
		http.Error(w, "error", http.StatusBadRequest)
		return
	}
	state.logger.Debugf(3, "top of webauthnBeginRegistration: after piece processing ")
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		state.logger.Debugf(1, "webauthnBeginRegistration: checkAuth Failed %v", err)
		return
	}
	state.logger.Debugf(3, "top of webauthnBeginRegistration: after authentication ")
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	// Check that they can change other users
	if !state.IsAdminUserAndU2F(authData.Username, authData.AuthType) &&
		authData.Username != assumedUser {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		state.logger.Printf("webauthnBeginRegistration: loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		state.logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
		return
	}
	state.logger.Debugf(3, "top of webauthnBeginRegistration: after profile loadingn ")

	profile.FixupCredential(assumedUser, assumedUser)
	state.logger.Debugf(2, "webauthnBeginRegistration profile=%+v", profile)
	state.logger.Debugf(2, "webauthnBeginRegistration: About to begin BeginRegistration")
	options, sessionData, err := state.webAuthn.BeginRegistration(profile)
	if err != nil {
		state.logger.Printf("webauthnBeginRegistration: begin login failed %s", err)
		// TODO: we should not be sending ALL the errors to clients
		webauthnJsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	localAuth := localUserData{
		WebAuthLogin: sessionData,
		ExpiresAt:    time.Now().Add(maxAgeU2FVerifySeconds * time.Second),
	}

	localDataIndex := localDataKey{username: assumedUser, dataType: localAuthTypeWebAuthRegistration}
	state.Mutex.Lock()
	state.localAuthData[localDataIndex] = localAuth
	state.Mutex.Unlock()
	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		state.logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	webauthnJsonResponse(w, options, http.StatusOK)
}

const webAutnRegististerFinishPath = "/webauthn/RegisterFinish/"

// verifyX5CChain checks an x5c array as found in an attestation statement.
// x5c[0] is the attestation certificate and each following element is
// expected to be the issuer of the previous one. All certificates must
// parse and be within their validity period at time now.
// This only verifies the internal consistency of the provided chain, trust
// anchors are checked by verifyAttestationX5C using the FIDO metadata.
func verifyX5CChain(x5c []any, now time.Time) error {
	if len(x5c) == 0 {
		return fmt.Errorf("x5c is present but empty")
	}
	certs := make([]*x509.Certificate, 0, len(x5c))
	for i, entry := range x5c {
		raw, ok := entry.([]byte)
		if !ok {
			return fmt.Errorf("x5c[%d] is not a byte string", i)
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("x5c[%d] parse error: %s", i, err)
		}
		logger.Printf("verifyChain cert[%i]=%+v", i, cert)
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("x5c[%d] (%s) is not valid at %s (valid %s to %s)",
				i, cert.Subject, now.Format(time.RFC3339),
				cert.NotBefore.Format(time.RFC3339),
				cert.NotAfter.Format(time.RFC3339))
		}
		certs = append(certs, cert)
	}
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return fmt.Errorf("x5c[%d] (%s) not signed by x5c[%d] (%s): %s",
				i, certs[i].Subject, i+1, certs[i+1].Subject, err)
		}
	}
	return nil
}

// x5cCommonName returns the subject common name of the first certificate of
// an x5c array, or the empty string if it cannot be parsed.
func x5cCommonName(x5c []any) string {
	if len(x5c) == 0 {
		return ""
	}
	raw, ok := x5c[0].([]byte)
	if !ok {
		return ""
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}

// verifyAttestationX5C verifies any x5c data present in the attestation
// statement (or in the sub statements of a compound attestation) of a
// credential creation response. When mds is not nil the attestation is also
// verified against the FIDO metadata, which checks the x5c chain against the
// trust anchors of the authenticator and its status reports.
// It returns the common name of the attestation certificate (x5c[0]) of the
// first statement that has one, even if the chain does not validate, and
// whether the attestation was validated against the FIDO metadata. Responses
// with no x5c data, or when mds is nil, are never validated. The returned
// error is only non nil on internal errors, invalid attestations are
// reported by returning false.
func verifyAttestationX5C(parsedResponse *protocol.ParsedCredentialCreationData,
	clientDataHash []byte, mds metadata.Provider,
	policy protocol.AttestationPolicy, signature protocol.SignaturePolicy,
	now time.Time) (string, bool, error) {
	if parsedResponse == nil {
		return "", false, fmt.Errorf("nil credential creation response")
	}
	attObj := &parsedResponse.Response.AttestationObject
	statements := []map[string]any{attObj.AttStatement}
	for _, sub := range attObj.SubStatements {
		statements = append(statements, sub.AttStatement)
	}
	var commonName string
	hasX5C := false
	chainsValid := true
	for _, stmt := range statements {
		rawX5C, ok := stmt["x5c"]
		if !ok {
			continue
		}
		hasX5C = true
		x5c, ok := rawX5C.([]any)
		if !ok {
			logger.Printf("verifyAttestationX5C: x5c is not an array")
			chainsValid = false
			continue
		}
		if commonName == "" {
			commonName = x5cCommonName(x5c)
		}
		if err := verifyX5CChain(x5c, now); err != nil {
			logger.Printf("verifyAttestationX5C: %s", err)
			chainsValid = false
		}
	}
	if !hasX5C || !chainsValid || mds == nil {
		return commonName, false, nil
	}
	if err := attObj.VerifyAttestation(clientDataHash, mds, policy, signature); err != nil {
		var protoErr *protocol.Error
		if !errors.As(err, &protoErr) {
			return commonName, false,
				fmt.Errorf("metadata verification error: %s", err)
		}
		logger.Printf("verifyAttestationX5C: metadata verification failed: %s (%s)",
			protoErr.Details, protoErr.DevInfo)
		return commonName, false, nil
	}
	logger.Debugf(1, "verifyAttestationX5C: verification succeeded")
	return commonName, true, nil
}

func (state *RuntimeState) webauthnFinishRegistration(w http.ResponseWriter, r *http.Request) {
	state.logger.Debugf(3, "top of webauthnFinishRegistration")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// TODO: better pattern matching
	// /u2f/RegisterRequest/<assumed user>
	// pieces[0] == "" pieces[1] = "u2f" pieces[2] == "RegisterRequest"
	pieces := strings.Split(r.URL.Path, "/")

	var assumedUser string
	if len(pieces) >= 4 {
		assumedUser = pieces[3]
	} else {
		http.Error(w, "error", http.StatusBadRequest)
		return
	}
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	// Check that they can change other users
	if !state.IsAdminUserAndU2F(authData.Username, authData.AuthType) &&
		authData.Username != assumedUser {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
		return
	}
	// load the session data
	// we use pair wise lock/unlocks as there could be long running
	// functions sucha as db updates and http responses.
	localDataIndex := localDataKey{username: assumedUser, dataType: localAuthTypeWebAuthRegistration}
	state.Mutex.Lock()
	localData, ok := state.localAuthData[localDataIndex] //check this
	state.Mutex.Unlock()
	if !ok {
		state.logger.Printf("unknown transaction for user")
		http.Error(w, "error", http.StatusBadRequest)
		return
	}
	if localData.ExpiresAt.Before(time.Now()) {
		state.logger.Printf("Expired Transaction")
		state.Mutex.Lock()
		delete(state.localAuthData, localDataIndex)
		state.Mutex.Unlock()
		http.Error(w, "error", http.StatusBadRequest)
		return

	}
	parsedResponse, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		state.logger.Println(err)
		webauthnJsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	state.logger.Debugf(2, "parsed reg response=%+v", parsedResponse)

	credential, err := state.webAuthn.CreateCredential(profile, *localData.WebAuthLogin, parsedResponse)
	if err != nil {
		state.logger.Println(err)
		webauthnJsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	state.logger.Debugf(2, "new credential=%+v\n", *credential)
	// CreateCredential has already verified the attestation signature, here
	// we verify the x5c chain (if any) including the FIDO metadata.
	attestationCN, fidoValidated, err := verifyAttestationX5C(parsedResponse,
		credential.Attestation.ClientDataHash, state.fidoMDS,
		state.webAuthn.Config.Attestation, state.webAuthn.Config.Signature,
		time.Now())
	if err != nil {
		state.logger.Printf("webauthnFinishRegistration: x5c verification error for %s: %s",
			assumedUser, err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	state.logger.Debugf(2, "webauthnFinishRegistration: user=%s attestation cn=%q fidoValidated=%t",
		assumedUser, attestationCN, fidoValidated)

	err = profile.AddWebAuthnCredential(*credential)
	if err != nil {
		state.logger.Printf("Saving adding credential error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		state.logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	state.Mutex.Lock()
	delete(state.localAuthData, localDataIndex) //TODO : maybe always clean?
	state.Mutex.Unlock()
	webauthnJsonResponse(w, "Registration Success", http.StatusOK)
}

const webAuthnAuthBeginPath = "/webauthn/AuthBegin/"

// We need to convert the auth request to the duo-labs proto as we need to be backwards compatible with clients
// The only difference is that the the encoding of some of the data, we need to keep this until cli clients
// have migrated to understand the new formatting.
func (state *RuntimeState) webauthAuthBeginResponseToOldProto(in protocol.CredentialAssertion) (*oldproto.CredentialAssertion, error) {
	state.logger.Debugf(4, " convert to old conversion in=%+v, ", in)
	serializedIn, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("error serializing err=%s", err)
	}
	var clone protocol.CredentialAssertion
	if err = json.Unmarshal(serializedIn, &clone); err != nil {
		return nil, fmt.Errorf("error marshaling serrializedIn err=%s", err)
	}
	// Here we will remove incompatible fields
	clone.Response.Challenge = nil
	for i, _ := range clone.Response.AllowedCredentials {
		clone.Response.AllowedCredentials[i].CredentialID = clone.Response.Challenge
	}
	serializedClone, err := json.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("failure to serialize clone err=%s", err)
	}
	var out oldproto.CredentialAssertion
	if err = json.Unmarshal(serializedClone, &out); err != nil {
		return nil, fmt.Errorf("error marshaling out err=%s", err)
	}
	// And now we reconstitute the incompatible fields
	out.Response.Challenge = []byte(in.Response.Challenge)
	for i, _ := range out.Response.AllowedCredentials {
		out.Response.AllowedCredentials[i].CredentialID = []byte(in.Response.AllowedCredentials[i].CredentialID)
	}
	// CLI clients use the appid as the clientData origin and fall back to
	// the bare RP ID without it. go-webauthn >= 0.18 drops the appid unless
	// a fido-u2f credential is present, so always send it to the client.
	if out.Response.Extensions == nil {
		out.Response.Extensions = oldproto.AuthenticationExtensions{}
	}
	out.Response.Extensions["appid"] = u2fAppID
	state.logger.Debugf(5, "conversion in=%+v, old=%+v", in, out)

	return &out, nil
}

func (state *RuntimeState) webauthnAuthLogin(w http.ResponseWriter, r *http.Request) {
	state.logger.Debugf(3, "top of webauthnAuthBegin")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		state.logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	profile, _, fromCache, err := state.LoadUserProfile(authData.Username)
	if err != nil {
		state.logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		state.logger.Debugf(1, "DB is being cached and requesting authentication, proceeding with cached values")
	}

	// TODO: there is an extension to ensure it is an actual secirity key... need to add this to the call.
	options, sessionData, err := state.webAuthn.BeginLogin(profile,
		webauthn.WithAssertionExtensions(webauthn.WithExtensionAppID(u2fAppID)))
	if err != nil {
		state.logger.Printf("webauthnAuthBegin: %s", err)
		webauthnJsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	c, err := u2f.NewChallenge(u2fAppID, u2fTrustedFacets)
	if err != nil {
		state.logger.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	c.Challenge, err = base64.RawURLEncoding.DecodeString(sessionData.Challenge)
	if err != nil {
		state.logger.Printf("webauthnAuthBegin base64  error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	var localAuth localUserData
	localAuth.U2fAuthChallenge = c
	localAuth.WebAuthnChallenge = sessionData
	localAuth.ExpiresAt = time.Now().Add(maxAgeU2FVerifySeconds * time.Second)
	localDataIndex := localDataKey{username: authData.Username, dataType: localAuthTypeWebAuthLogin}
	state.Mutex.Lock()
	state.localAuthData[localDataIndex] = localAuth
	state.Mutex.Unlock()
	compatOptions, err := state.webauthAuthBeginResponseToOldProto(*options)
	if err != nil {
		state.logger.Printf("webauthnAuthBegin convert to old  error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	webauthnJsonResponse(w, compatOptions, http.StatusOK)
	state.logger.Debugf(3, "end of webauthnAuthBegin")
}

const webAuthnAuthFinishPath = "/webauthn/AuthFinish/"

func (state *RuntimeState) webauthnAuthFinish(w http.ResponseWriter, r *http.Request) {
	state.logger.Debugf(3, "top of webauthnAuthFinish")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	profile, ok, _, err := state.LoadUserProfile(authData.Username)
	if err != nil {
		state.logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if !ok {
		http.Error(w, "No regstered data", http.StatusBadRequest)
		return
	}

	localDataIndex := localDataKey{username: authData.Username, dataType: localAuthTypeWebAuthLogin}
	state.Mutex.Lock()
	localAuth, ok := state.localAuthData[localDataIndex]
	state.Mutex.Unlock()
	if !ok {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		state.logger.Printf("Error parsing Response err =%s", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	userCredentials := profile.WebAuthnCredentials()
	var loginCredential webauthn.Credential
	var credentialFound bool
	var credentialIndex int64
	for _, cred := range userCredentials {
		if cred.AttestationType != "fido-u2f" {
			continue
		}
		if bytes.Equal(cred.ID, parsedResponse.RawID) {
			loginCredential = cred
			credentialFound = true
			for i, u2fReg := range profile.U2fAuthData {
				if !u2fReg.Enabled {
					continue
				}
				if bytes.Equal(u2fReg.Registration.KeyHandle, parsedResponse.RawID) {
					credentialIndex = i
				}
			}

			break
		}
		credentialFound = false
	}

	verifiedAuth := authData.AuthType
	if !credentialFound {
		// DO STD webaautn verification
		_, err = state.webAuthn.ValidateLogin(profile, *localAuth.WebAuthnChallenge, parsedResponse) // iFinishLogin(profile, *localAuth.WebAuthnChallenge, r)
		if err != nil {
			state.logger.Printf("webauthnAuthFinish: auth failure err=%s", err)
			webauthnJsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO also update the profile with latest counter
		verifiedAuth = AuthTypeFIDO2
	} else {
		// NOTE: somehow the extensions for grabbing the appID are failing
		// So we "unroll" the important pieces of webAuthn.ValidateLogin here, with
		// explicit changes for our appID
		// Notice that if we where strict we would iterate over all the alloowed values.
		session := *localAuth.WebAuthnChallenge
		shouldVerifyUser := session.UserVerification == protocol.VerificationRequired

		rpID := state.webAuthn.Config.RPID
		rpOrigins := state.webAuthn.Config.RPOrigins
		appID := u2fAppID

		// func (p *ParsedCredentialAssertionData) Verify(storedChallenge string, relyingPartyID string, rpOrigins, rpTopOrigins []string, rpTopOriginsVerify TopOriginVerificationMode, appID string, verifyUser bool, credentialBytes []byte) error {
		// Handle steps 4 through 16
		rpTopOrigins := rpOrigins // FIXME: we actually have to compute this
		verifyUserPresence := true
		rpOpaqueOrigins := []string{}
		allowCrossOrigin := false
		validError := parsedResponse.Verify(session.Challenge, rpID, appID, rpOrigins, rpOpaqueOrigins, rpTopOrigins,
			protocol.TopOriginAutoVerificationMode,
			allowCrossOrigin, shouldVerifyUser, verifyUserPresence, loginCredential.PublicKey, protocol.SignaturePolicy{})
		if validError != nil {
			state.logger.Printf("failed to verify webauthn parsedResponse")
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "Credential Not Found")
			return
		}

		//loginCredential.Authenticator.UpdateCounter(parsedResponse.Response.AuthenticatorData.Counter)
		u2fReg, ok := profile.U2fAuthData[credentialIndex]
		if ok {
			u2fReg.Counter = parsedResponse.Response.AuthenticatorData.Counter
			profile.U2fAuthData[credentialIndex] = u2fReg
			go state.SaveUserProfile(authData.Username, profile)
		}

		verifiedAuth = AuthTypeU2F
		state.logger.Debugf(3, "success (LOCAL)")
	}
	state.logger.Debugf(1, "webauthnAuthFinish: auth success")

	// TODO: disinguish better between the two protocols or just use one
	//metricLogAuthOperation(getClientType(r), proto.AuthTypeU2F, true)
	state.Mutex.Lock()
	delete(state.localAuthData, localDataIndex)
	state.Mutex.Unlock()

	//TODO: distinguish here u2f vs webauthn
	eventNotifier.PublishAuthEvent(eventmon.AuthTypeU2F, authData.Username)
	_, isXHR := r.Header["X-Requested-With"]
	if isXHR {
		eventNotifier.PublishWebLoginEvent(authData.Username)
	}

	_, err = state.updateAuthCookieAuthlevel(w, r,
		authData.AuthType|verifiedAuth|AuthTypeU2F)
	if err != nil {
		logger.Printf("Auth Cookie NOT found ? %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure updating vip token")
		return
	}
	webauthnJsonResponse(w, "Login Success", http.StatusOK)
}
