package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
)

type KeyPreference int

const (
	RSASigner KeyPreference = iota
	P256Signer
	P384Signer
)

// names:
// ecdsa-sha2-nistp256-cert-v01
// ecdsa-sha2-nistp384

func keyPreferenceFromString(stringPref string) (KeyPreference, error) {
	switch stringPref {
	case "rsa":
		return RSASigner, nil
	case "p256":
		return P256Signer, nil
	case "p384":
		return P384Signer, nil
	default:
		return 0, fmt.Errorf("uknown name")
	}
}

type signers struct {
	mutex      sync.RWMutex
	err        error
	X509       crypto.Signer
	SshMain    crypto.Signer
	SshEd25519 ed25519.PrivateKey
	keyPref    KeyPreference
}

func makeSigners(keyPreference KeyPreference) *signers {
	s := signers{
		keyPref: keyPreference,
	}
	s.mutex.Lock()
	go s.compute()
	return &s
}

func (s *signers) compute() {
	defer s.mutex.Unlock()
	var err error
	var err2 error
	switch s.keyPref {
	case RSASigner:
		s.X509, err = rsa.GenerateKey(rand.Reader, rsaKeySize)
		s.SshMain, err2 = rsa.GenerateKey(rand.Reader, rsaKeySize)
	case P256Signer:
		s.X509, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		s.SshMain, err2 = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case P384Signer:
		s.X509, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		s.SshMain, err2 = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		err = fmt.Errorf("uknown signer preference")
	}
	if err != nil || err2 != nil {
		s.err = err
		if err2 != nil {
			s.err = err
		}
		return
	}
	_, sshEd25519Signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.err = err
		return
	}
	s.SshEd25519 = sshEd25519Signer
}

// Wait must be called before accessing any of the signers.
func (s *signers) Wait() error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.err
}
