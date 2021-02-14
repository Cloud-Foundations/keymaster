// Package configutil contains utility routines for the keymaster client.
package util

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"net/http"
	"os/user"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/client/net"
)

// GetUserCreds prompts the user for thier password and returns it.
func GetUserCreds(userName string) (password []byte, err error) {
	return getUserCreds(userName)
}

// GetUserHomeDir returns the user's home directory.
func GetUserHomeDir(usr *user.User) (string, error) {
	// TODO: verify on Windows... see: http://stackoverflow.com/questions/7922270/obtain-users-home-directory
	return usr.HomeDir, nil
}

// GenKeyPair uses internal golang functions to be portable
func GenKeyPair(
	privateKeyPath string, identity string, logger log.Logger) (
	privateKey crypto.Signer, publicKeyPath string, err error) {
	return genKeyPair(privateKeyPath, identity, logger)
}

// GetHttpClient returns an http client instance to use given a
// particular TLS configuration.
func GetHttpClient(tlsConfig *tls.Config,
	dialer net.Dialer) (*http.Client, error) {
	return getHttpClient(tlsConfig, dialer)
}

// GenerateKey generates a random 2048 byte rsa key
func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeySize)
}
