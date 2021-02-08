package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/Cloud-Foundations/golib/pkg/awsutil/metadata"
	"github.com/Cloud-Foundations/golib/pkg/awsutil/secretsmgr"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
)

func (config *autoUnseal) applyDefaults() {
	if config.AwsSecretKey == "" {
		config.AwsSecretKey = "UnsealPassword"
	}
}

func (state *RuntimeState) checkSealedHandler(w http.ResponseWriter,
	r *http.Request) {
	w.WriteHeader(200)
	if state.Signer == nil {
		fmt.Fprintf(w, "SEALED\n")
	} else {
		fmt.Fprintf(w, "UNSEALED\n")
	}
}

func (state *RuntimeState) secretInjectorHandler(w http.ResponseWriter,
	r *http.Request) {
	// checks this is only allowed when using TLS client certs.. all other authn
	// mechanisms are considered invalid... for now no authz mechanisms are in
	// place i.e. Any user with a valid cert can use this handler
	if r.TLS == nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("We require TLS\n")
		return
	}
	if len(r.TLS.VerifiedChains) < 1 {
		state.writeFailureResponse(w, r, http.StatusForbidden, "")
		logger.Printf("Forbidden\n")
		return
	}
	clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
	logger.Printf("Got connection from %s", clientName)
	r.ParseForm()
	sshCAPassword, ok := r.Form["ssh_ca_password"]
	if !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Invalid Post, missing data")
		logger.Printf("missing ssh_ca_password")
		return
	}
	if err := state.unsealCA([]byte(sshCAPassword[0]), clientName); err != nil {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Invalid Post, "+err.Error())
		logger.Println(err)
		return
	}
	w.WriteHeader(200)
	fmt.Fprintf(w, "OK\n")
	//fmt.Fprintf(w, "%+v\n", r.TLS)
}

func (state *RuntimeState) beginAutoUnseal() {
	go state.autoUnsealAwsLoop()
}

func (state *RuntimeState) autoUnsealAwsLoop() {
	if state.Config.Base.AutoUnseal.AwsSecretId == "" {
		return
	}
	metadataClient, err := metadata.GetMetadataClient()
	if err != nil {
		state.logger.Println(err)
		return
	}
	for {
		if state.isUnsealed() {
			return
		}
		if err := state.tryAwsUnseal(metadataClient); err != nil {
			state.logger.Printf(
				"error unsealing with AWS Secrets Manager: %s\n", err)
			state.logger.Println("will try again")
			time.Sleep(time.Minute * 5)
		} else {
			return
		}
	}
}

func (state *RuntimeState) isUnsealed() bool {
	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	return state.Signer != nil
}

func (state *RuntimeState) tryAwsUnseal(
	metadataClient *ec2metadata.EC2Metadata) error {
	config := state.Config.Base.AutoUnseal
	secrets, err := secretsmgr.GetAwsSecret(metadataClient, config.AwsSecretId,
		state.logger)
	if err != nil {
		return err
	}
	password, ok := secrets[config.AwsSecretKey]
	if !ok {
		return fmt.Errorf("key: %s not found in secret", config.AwsSecretKey)
	}
	return state.unsealCA([]byte(password), "AWS Secrets Manager")
}

func (state *RuntimeState) unsealCA(password []byte, clientName string) error {
	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	// TODO.. make network error blocks to goroutines
	if state.Signer != nil {
		return errors.New("signer not null, already unlocked")
	}
	decbuf := bytes.NewBuffer(state.SSHCARawFileContent)
	armorBlock, err := armor.Decode(decbuf)
	if err != nil {
		return errors.New("cannot decode armored file")
	}
	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		// If the given passphrase isn't correct, the function will be called
		// again, forever.
		// This method will fail fast.
		// Ref: https://godoc.org/golang.org/x/crypto/openpgp#PromptFunction
		if failed {
			return nil, errors.New("decryption failed")
		}
		failed = true
		return password, nil
	}
	md, err := openpgp.ReadMessage(armorBlock.Body, nil, prompt, nil)
	if err != nil {
		return fmt.Errorf("cannot decrypt key: %s", err)
	}
	plaintextBytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return err
	}
	signer, err := getSignerFromPEMBytes(plaintextBytes)
	if err != nil {
		fmt.Errorf("cannot parse Private Key file: %s", err)
	}
	logger.Printf("About to generate CA DER %s", clientName)
	state.caCertDer, err = generateCADer(state, signer)
	if err != nil {
		return fmt.Errorf("cannot generate CA DER: %s", err)
	}
	sendMessage := false
	if state.Signer == nil {
		sendMessage = true
	}
	// Assignment of signer MUST be the last operation after all error checks.
	state.Signer = signer
	state.signerPublicKeyToKeymasterKeys()
	if sendMessage {
		state.SignerIsReady <- true
	}
	// TODO... make success a goroutine
	return nil
}
