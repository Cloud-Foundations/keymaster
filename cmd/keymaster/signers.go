package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

type signers struct {
	mutex      sync.RWMutex
	err        error
	X509       crypto.Signer
	SshRsa     crypto.Signer
	SshEd25519 ed25519.PrivateKey
	keyPref    KeyPreference
}

func makeSigners() *signers {
	s := signers{}
	s.mutex.Lock()
	go s.compute()
	return &s
}

func (s *signers) compute() {
	defer s.mutex.Unlock()
	var err error
	switch s.keyPref {
	case P256Signer:
		s.X509, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case P384Signer:
		s.X509, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		//rsa is default for backwars compatibilty
		s.X509, err = rsa.GenerateKey(rand.Reader, rsaKeySize)

	}
	if err != nil {
		s.err = err
		return
	}
	sshRsaSigner, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	//sshRsaSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		s.err = err
		return
	}
	_, sshEd25519Signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.err = err
		return
	}
	s.SshRsa = sshRsaSigner
	s.SshEd25519 = sshEd25519Signer
}

// Wait must be called before accessing any of the signers.
func (s *signers) Wait() error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.err
}
