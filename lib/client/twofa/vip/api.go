// Package vip does two factor authentication with Symantec VIP
package vip

import (
	"net/http"

	"github.com/Cloud-Foundations/Dominator/lib/log"
)

// DoVIPAuthenticate performs two factor authentication with Symantec VIP
func DoVIPAuthenticate(
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {
	return doVIPAuthenticate(client, baseURL, userAgentString, logger)
}
