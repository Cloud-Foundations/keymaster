// Package twofa contains routines for getting short lived certificate.
package twofa

import (
	"crypto"
	"flag"
	"net/http"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
)

var (
	// Duration of generated cert. Default 16 hours.
	Duration = flag.Duration("duration", 16*time.Hour, "Duration of the requested certificates in golang duration format (ex: 30s, 5m, 12h)")
	// If set, Do not use U2F as second factor
	noU2F = flag.Bool("noU2F", false, "Don't use U2F as second factor")
	// If set, Do not use TOTP as second factor
	noTOTP = flag.Bool("noTOTP", false, "Don't use TOTP as second factor")
	// If set, Do not use VIPAccess as second factor.
	noVIPAccess = flag.Bool("noVIPAccess", false, "Don't use VIPAccess as second factor")
)

// Getter and setter functions for the flags
func SetNoU2F(value bool) {
	*noU2F = value
}

func GetNoU2F() bool {
	return *noU2F
}

func SetNoTOTP(value bool) {
	*noTOTP = value
}

func GetNoTOTP() bool {
	return *noTOTP
}

func SetNoVIPAccess(value bool) {
	*noVIPAccess = value
}

func GetNoVIPAccess() bool {
	return *noVIPAccess
}

// AuthenticateToTargetUrls does an authentication to the keymasted server
// it performs 2fa if needed using the server side specified methods
// it assumes the http client has a valid cookiejar
func AuthenticateToTargetUrls(
	userName string,
	password []byte,
	targetUrls []string,
	skip2fa bool,
	client *http.Client,
	userAgentString string,
	logger log.DebugLogger) (baseUrl string, err error) {
	return authenticateToTargetUrls(userName, password, targetUrls, skip2fa, client,
		userAgentString, logger)
}

// After a client has authenticated it can call DoCertRequest for the appropiate type
func DoCertRequest(signer crypto.Signer, client *http.Client, userName string,
	baseUrl,
	certType string,
	addGroups bool,
	userAgentString string, logger log.DebugLogger) ([]byte, error) {
	return doCertRequest(signer, client, userName, baseUrl,
		certType, addGroups,
		userAgentString, logger)
}
