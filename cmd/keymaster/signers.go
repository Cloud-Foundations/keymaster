package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"sync"
)

type signers struct {
	mutex      sync.RWMutex
	err        error
	X509Rsa    *rsa.PrivateKey
	SshRsa     *rsa.PrivateKey
	SshEd25519 ed25519.PrivateKey
}

func makeSigners() *signers {
	s := signers{}
	s.mutex.Lock()
	go s.compute()
	return &s
}

func (s *signers) compute() {
	defer s.mutex.Unlock()
	x509Signer, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		s.err = err
		return
	}
	sshRsaSigner, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		s.err = err
		return
	}
	_, sshEd25519Signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.err = err
		return
	}
	s.X509Rsa = x509Signer
	s.SshRsa = sshRsaSigner
	s.SshEd25519 = sshEd25519Signer
}

// Wait must be called before accessing any of the signers.
func (s *signers) Wait() error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.err
}
