package main

import (
	"net/http"
	"os"
	"testing"

	"github.com/Cloud-Foundations/Dominator/lib/log/serverlogger"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/cviecco/webauth-sshcert/lib/server/sshcertauth"
)

func TestInitializeSSHAuthenticator(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.sshCertAuthenticator = sshcertauth.NewAuthenticator(
		[]string{state.HostIdentity}, []string{})
	err = state.initialzeSelfSSHCertAuthenticator()
	if err != nil {
		t.Fatal(err)
	}
}

func TestIsSelfSSHCertAuthenticatorEnabled(t *testing.T) {
	state := RuntimeState{}
	if state.isSelfSSHCertAuthenticatorEnabled() {
		t.Fatal("it should not be enabled on empty state")
	}
	state.Config.Base.AllowedAuthBackendsForCerts = append(state.Config.Base.AllowedAuthBackendsForCerts, proto.AuthTypeSSHCert)
	if !state.isSelfSSHCertAuthenticatorEnabled() {
		t.Fatal("it should be enabled on empty state")
	}
}

func TestSshCertAuthCreateChallengeHandlert(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.sshCertAuthenticator = sshcertauth.NewAuthenticator(
		[]string{state.HostIdentity}, []string{})
	err = state.initialzeSelfSSHCertAuthenticator()
	if err != nil {
		t.Fatal(err)
	}
	// make call with bad data
	//initially the request should fail for lack of preconditions
	req, err := http.NewRequest("POST", redirectPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	// oath2 config is invalid
	_, err = checkRequestHandlerCode(req, state.sshCertAuthCreateChallengeHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}
	// simulaet good call, ignore result for now
	goodURL := "foobar?nonce1=12345678901234567890123456789"
	// TODO: replce this for a post
	req2, err := http.NewRequest("GET", goodURL, nil)
	_, err = checkRequestHandlerCode(req2, state.sshCertAuthCreateChallengeHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSshCertAuthLoginWithChallengeHandler(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.Config.Base.AllowedAuthBackendsForCerts = append(state.Config.Base.AllowedAuthBackendsForCerts, proto.AuthTypeSSHCert)
	realLogger := serverlogger.New("") //TODO, we need to find a simulator for this
	adminMux := http.NewServeMux()
	startServerAfterLoad(state, adminMux, realLogger)

	//TODO: write the actual test, at this point we only have the endpoints initalized
}
