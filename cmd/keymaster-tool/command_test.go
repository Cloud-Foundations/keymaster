package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
)

// X509 from certgen.go... maybe move to util?
func getPubKeyFromPem(pubkey string) (pub interface{}, err error) {
	block, rest := pem.Decode([]byte(pubkey))
	if block == nil || block.Type != "PUBLIC KEY" {
		err := fmt.Errorf("Cannot decode user public Key '%s' rest='%s'", pubkey, string(rest))
		if block != nil {
			err = fmt.Errorf("public key bad type %s", block.Type)
		}
		return nil, err
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func TestSerializePublicKey(t *testing.T) {
	//var publicKeySet []crypto.PublicKey
	ed255Public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	allowedFormats := []string{"ssh", "pem"}
	for _, format := range allowedFormats {
		var serializedBuffer bytes.Buffer
		err = serializePublic(ed255Public, format, &serializedBuffer)
		if err != nil {
			t.Fatal(err)
		}
		var parsedPublic crypto.PublicKey
		switch format {
		case "pem":
			parsedPublic, err = getPubKeyFromPem(serializedBuffer.String())
			if err != nil {
				t.Fatal(err)
			}
		case "ssh":
			sshParsedPublic, _, _, _, err := ssh.ParseAuthorizedKey(serializedBuffer.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			cp, ok := sshParsedPublic.(ssh.CryptoPublicKey)
			if !ok {
				t.Fatalf("not convertable publicc")
			}
			parsedPublic = cp.CryptoPublicKey()
		}
		if !ed255Public.Equal(parsedPublic) {
			t.Fatalf("keys dont match")
		}

	}

}

func TestGenerateDecryptRoundTrip(t *testing.T) {
	passPhrase := []byte("1234")
	keyTypes := []string{"ed25519", "rsa"}
	outFormat := "pem"
	logger := testlogger.New(t)

	for _, keyType := range keyTypes {
		var encryptedBuffer bytes.Buffer
		pubkey, err := generateNewKeyPair(passPhrase, keyType, &encryptedBuffer, logger)
		if err != nil {
			t.Fatal(err)
		}
		var serializedPublic bytes.Buffer
		err = printPublicKey(passPhrase, &encryptedBuffer, outFormat, &serializedPublic, logger)
		if err != nil {
			t.Fatal(err)
		}
		if outFormat != "pem" {
			continue
		}
		decrypedPub, err := getPubKeyFromPem(serializedPublic.String())
		if err != nil {
			t.Fatal(err)
		}
		switch k := pubkey.(type) {
		case *ed25519.PublicKey: //, ed25519.PublicKey:
			if !k.Equal(decrypedPub) {
				t.Fatalf("non matching ed25519 public")
			}
		case ed25519.PublicKey:
			if !k.Equal(decrypedPub) {
				t.Fatalf("non matching ed25519 public")
			}
		case *rsa.PublicKey:
			if !k.Equal(decrypedPub) {
				t.Fatalf("non matching rsa public")
			}
		//  case *ecdsa.PublicKey:
		default:
			t.Fatalf("unknown public key type")
		}
	}

}
