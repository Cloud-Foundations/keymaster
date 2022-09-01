package aws_identity_cert

import (
	"crypto/x509"
	"net/http"

	presignc "github.com/Cloud-Foundations/golib/pkg/awsutil/presignauth/caller"
	"github.com/Cloud-Foundations/golib/pkg/log"
)

type Issuer struct {
	presignCallerClient presignc.Caller
	params              Params
}

type Params struct {
	// Required parameters.
	CertificateGenerator func(template *x509.Certificate,
		publicKey interface{}) ([]byte, error)
	// Optional parameters.
	AccountIdValidator func(accountId string) bool
	FailureWriter      func(w http.ResponseWriter, r *http.Request,
		errorString string, code int)
	HttpClient *http.Client
	Logger     log.DebugLogger
}

// New will create a certificate issuer for AWS IAM identity certificates.
func New(params Params) (*Issuer, error) {
	return newIssuer(params)
}

// RequestHandler implements a REST interface that will respond with a signed
// X.509 Certificate for a request with a pre-signed URL from the AWS
// Security Token Service (STS). This pre-signed URL is used to verify the
// identity of the caller.
// The request must contain the following headers:
// Claimed-Arn:      the full AWS Role ARN
// Presigned-Method: the method type specified in the pre-signing response
// Presigned-URL:    the URL specified in the pre-signing response
// The body of the request must contain a PEM-encoded Public Key DER.
// On success, the response body will contain a signed, PEM-encoded X.509
// Certificate and the Certificate template is returned.
func (i *Issuer) RequestHandler(w http.ResponseWriter,
	r *http.Request) *x509.Certificate {
	return i.requestHandler(w, r)
}
