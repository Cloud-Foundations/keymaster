package aws_role

import (
	"context"
	"crypto"
	"crypto/tls"
	"net/http"
	"sync"

	"github.com/Cloud-Foundations/golib/pkg/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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
	awsConfig  aws.Config
	derPubKey  []byte
	isSetup    bool
	pemPubKey  []byte
	roleArn    string
	stsClient  *sts.Client
}

type Manager struct {
	Params
	mutex    sync.RWMutex // Protect everything below.
	tlsCert  *tls.Certificate
	tlsError error
}

// GetRoleCertificate requests an AWS role identify certificate from the
// Keymaster server specified in params. It returns the certificate PEM.
func GetRoleCertificate(params Params) ([]byte, error) {
	return params.getRoleCertificate()
}

// GetRoleCertificateTLS requests an AWS role identify certificate from the
// Keymaster server specified in params. It returns the certificate.
func GetRoleCertificateTLS(params Params) (*tls.Certificate, error) {
	return params.getRoleCertificateTLS()
}

// NewManager returns a certificate manager which provides AWS role identity
// certificates from the Keymaster server specified in params. Certificates
// are refreshed in the background.
func NewManager(params Params) (*Manager, error) {
	return newManager(params)
}

// GetClientCertificate returns a valid, cached certificate.
func (m *Manager) GetClientCertificate(cri *tls.CertificateRequestInfo) (
	*tls.Certificate, error) {
	return m.getClientCertificate(cri)
}
