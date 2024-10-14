package main

import (
	"net/http"
	"os"
	"testing"

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
