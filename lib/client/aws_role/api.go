package aws_role

import (
	"context"
	"crypto"
	"net/http"

	"github.com/Cloud-Foundations/golib/pkg/log"
)

type Params struct {
	// Required parameters.
	KeymasterServer string
	Logger          log.DebugLogger
	// Optional parameters.
	Context    context.Context
	HttpClient *http.Client
	KeyType    string // "RSA"
	Signer     crypto.Signer
	derPubKey  []byte
	pemPubKey  []byte
}

// GetRoleCertificate requests an AWS role identify certificate from the
// Keymaster server specified in params. It returns the certificate PEM.
func GetRoleCertificate(params Params) ([]byte, error) {
	return params.getRoleCertificate()
}
