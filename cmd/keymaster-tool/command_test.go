package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

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

func TestEncryptDecrypt(t *testing.T) {
	passPhrase := "1234"
	inData := "123456781234567"
	var plaintextBuffer bytes.Buffer
	_, err := plaintextBuffer.Write([]byte(inData))
	if err != nil {
		t.Fatal(err)
	}
	armoredBytes, err := armorEncryptBytes(plaintextBuffer.Bytes(), []byte(passPhrase))
	if err != nil {
		t.Fatal(err)
	}
	outData, err := pgpDecryptFileData(armoredBytes, []byte(passPhrase))
	if err != nil {
		t.Fatal(err)
	}
	equal := bytes.Equal([]byte(inData), outData)
	if !equal {
		t.Fatal("roundtrip fail")
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
