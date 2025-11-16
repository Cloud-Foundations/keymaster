package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Cloud-Foundations/webauth-sshcert/lib/client/sshautn"
	"github.com/Cloud-Foundations/webauth-sshcert/lib/server/sshcertauth"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/publicsuffix"
)

/// create challenge.. does not require anything

/// login with challenge

// 1. Create server keypair
// 2. Add server keypair to trusted set
// 3. Create test ssh-cert
// 4. Create test webport
// 5. Create new client (with cookie store)
// 6. Add signer cert to client
// 7. Make client do both calls
// 8. Ensure client has valid auth cookie/

func TestCreateChallengeHandlerMinimal(t *testing.T) {
	// This test just tests the happy path
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	sshSigner, err := ssh.NewSignerFromSigner(state.Signer)
	if err != nil {
		t.Fatal(err)
	}
	signerPub := ssh.MarshalAuthorizedKey(sshSigner.PublicKey())
	t.Logf("signerpub ='%s'", string(signerPub))

	state.websshauthenticator = sshcertauth.NewAuthenticator([]string{"localhost", "127.0.0.1"}, []string{string(signerPub)})
	// TODO: This should be eventually be provided by the state
	serverMux := http.NewServeMux()
	serverMux.HandleFunc(sshcertauth.DefaultCreateChallengePath, state.CreateChallengeHandler)
	serverMux.HandleFunc(sshcertauth.DefaultLoginWithChallengePath, state.LoginWithChallengeHandler)

	// To isolate into separate function
	userPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPrivateKey.Public()
	t.Logf("userPub is %T", userPub)
	sshPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	currentEpoch := uint64(time.Now().Unix())
	expireEpoch := currentEpoch + uint64(30)
	cert := ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		SignatureKey:    sshSigner.PublicKey(),
		ValidPrincipals: []string{"someuser"},
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
	}
	err = cert.SignCert(bytes.NewReader(cert.Marshal()), sshSigner)
	if err != nil {
		t.Fatal(err)
	}
	//

	// now we start plugging the setup
	ts := httptest.NewTLSServer(serverMux)
	defer ts.Close()
	client := ts.Client()
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}
	client.Jar = jar

	keyring := agent.NewKeyring()
	toAdd := agent.AddedKey{
		PrivateKey:   userPrivateKey,
		Certificate:  &cert,
		LifetimeSecs: 10,
	}
	err = keyring.Add(toAdd)
	if err != nil {
		t.Fatal(err)
	}
	a, err := sshautn.NewAuthenticator(ts.URL, client)
	if err != nil {
		t.Fatal(err)
	}
	//a.LogLevel = 10
	returnedBody, _, err := a.DoLoginWithAgent(keyring)
	if err != nil {
		t.Fatal(err)
	}
	// TODO actually check returned data + cookie values
	fmt.Printf("%s", returnedBody)

}
