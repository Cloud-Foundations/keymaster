package main

import (
	"encoding/json"
	"net/http"

	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"golang.org/x/crypto/ssh"
)

// This function can only be called after all known keymaster public keys
// have been loaded, that is, after the server is ready
func (state *RuntimeState) initialzeSelfSSHCertAuthenticator() error {

	// build ssh pubkey list
	var sshTrustedKeys []string
	for _, pubkey := range state.KeymasterPublicKeys {
		sshPubkey, err := ssh.NewPublicKey(pubkey)
		if err != nil {
			return err
		}
		authorizedKey := ssh.MarshalAuthorizedKey(sshPubkey)
		sshTrustedKeys = append(sshTrustedKeys, string(authorizedKey))
	}
	return state.sshCertAuthenticator.UnsafeUpdateCaKeys(sshTrustedKeys)
}

func (state *RuntimeState) isSelfSSHCertAuthenticatorEnabled() bool {
	for _, certPref := range state.Config.Base.AllowedAuthBackendsForCerts {
		if certPref == proto.AuthTypeSSHCert {
			return true
		}
	}
	return false
}

// CreateChallengeHandler is an example of how to write a handler for
// the path to create the challenge
func (s *RuntimeState) sshCertAuthCreateChallengeHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: add some rate limiting
	err := s.sshCertAuthenticator.CreateChallengeHandler(w, r)
	if err != nil {
		// we are assuming bad request
		s.logger.Debugf(1,
			"CreateSSHCertAuthChallengeHandler: there was an err computing challenge: %s", err)
		s.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Operation")
		return
	}
}

func (s *RuntimeState) sshCertAuthLoginWithChallengeHandler(w http.ResponseWriter, r *http.Request) {
	username, expiration, userErrString, err := s.sshCertAuthenticator.LoginWithChallenge(r)
	if err != nil {
		s.logger.Printf("error=%s", err)
		errorCode := http.StatusBadRequest
		if userErrString == "" {
			errorCode = http.StatusInternalServerError
		}
		s.writeFailureResponse(w, r, errorCode, userErrString)
		return
	}
	// Make new auth cookie
	_, err = s.setNewAuthCookieWithExpiration(w, username, AuthTypeKeymasterSSHCert, expiration)
	if err != nil {
		s.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		s.logger.Println(err)
		return
	}

	// TODO: The cert backend should depend also on per user preferences.
	loginResponse := proto.LoginResponse{Message: "success"}
	// TODO needs eventnotifier?
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(loginResponse)
}
