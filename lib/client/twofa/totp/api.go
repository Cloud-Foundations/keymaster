// Package twofa contains routines for getting short lived certificate.
package totp

import (
	"net/http"

	"github.com/Cloud-Foundations/golib/pkg/log"
)

// DoTOTPAuthenticate does TOTP authentication
func DoTOTPAuthenticate(
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {
	return doTOTPAuthenticate(client, baseURL, userAgentString, logger)
}
