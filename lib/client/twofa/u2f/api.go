// Package twofa contains routines for getting short lived certificate.
package u2f

import (
	"net/http"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/marshallbrekka/go-u2fhost"
)

// CheckU2FDevices checks the U2F devices and terminates the application by
// calling Fatal on the passed logger if the U2F devices cannot be read.
func CheckU2FDevices(logger log.Logger) {
	checkU2FDevices(logger)
}

// DoU2FAuthenticate does U2F authentication
func DoU2FAuthenticate(
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {
	return doU2FAuthenticate(client, baseURL, userAgentString, logger)
}

func WithDevicesDoU2FAuthenticate(
	devices []*u2fhost.HidDevice,
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {
	return withDevicesDoU2FAuthenticate(devices, client, baseURL, userAgentString, logger)
}
