package aws_role

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/paths"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const rsaKeySize = 2048

func parseArn(arnString string) (*arn.ARN, error) {
	parsedArn, err := arn.Parse(arnString)
	if err != nil {
		return nil, err
	}
	switch parsedArn.Service {
	case "iam", "sts":
	default:
		return nil, fmt.Errorf("unsupported service: %s", parsedArn.Service)
	}
	splitResource := strings.Split(parsedArn.Resource, "/")
	if len(splitResource) < 2 || splitResource[0] != "assumed-role" {
		return nil, fmt.Errorf("invalid resource: %s", parsedArn.Resource)
	}
	// Normalise to the actual role ARN, rather than an ARN showing how the
	// credentials were obtained. This mirrors the way AWS policy documents are
	// written.
	parsedArn.Region = ""
	parsedArn.Service = "iam"
	parsedArn.Resource = "role/" + splitResource[1]
	return &parsedArn, nil
}

func newManager(p Params) (*Manager, error) {
	certPEM, certTLS, err := p.getRoleCertificateTLS()
	if err != nil {
		return nil, err
	}
	p.Logger.Printf("got AWS Role certificate for: %s\n", p.roleArn)
	manager := &Manager{
		params:  p,
		certPEM: certPEM,
		certTLS: certTLS,
		waiters: make(map[chan<- struct{}]struct{}),
	}
	go manager.refreshLoop()
	return manager, nil
}

func (m *Manager) getClientCertificate(cri *tls.CertificateRequestInfo) (
	*tls.Certificate, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.certTLS, m.certError
}

func (m *Manager) getRoleCertificate() ([]byte, *tls.Certificate, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.certPEM, m.certTLS, m.certError
}

func (m *Manager) refreshLoop() {
	for ; ; time.Sleep(time.Minute) {
		m.refreshOnce()
	}
}

func (m *Manager) refreshOnce() {
	if m.certTLS != nil {
		refreshTime := m.certTLS.Leaf.NotBefore.Add(
			m.certTLS.Leaf.NotAfter.Sub(m.certTLS.Leaf.NotBefore) * 3 / 4)
		duration := time.Until(refreshTime)
		m.params.Logger.Debugf(1, "sleeping: %s before refresh\n",
			(duration + time.Millisecond*50).Truncate(time.Millisecond*100))
		time.Sleep(duration)
	}
	if certPEM, certTLS, err := m.params.getRoleCertificateTLS(); err != nil {
		m.params.Logger.Println(err)
		if m.certTLS == nil {
			m.mutex.Lock()
			m.certError = err
			m.mutex.Unlock()
		}
	} else {
		m.mutex.Lock()
		m.certError = nil
		m.certPEM = certPEM
		m.certTLS = certTLS
		for waiter := range m.waiters {
			select {
			case waiter <- struct{}{}:
			default:
			}
			delete(m.waiters, waiter)
		}
		m.mutex.Unlock()
		m.params.Logger.Printf("refreshed AWS Role certificate for: %s\n",
			m.params.roleArn)
	}
}

func (m *Manager) waitForRefresh() {
	ch := make(chan struct{}, 1)
	m.mutex.Lock()
	m.waiters[ch] = struct{}{}
	m.mutex.Unlock()
	<-ch
}

// Returns certificate PEM block.
func (p *Params) getRoleCertificate() ([]byte, error) {
	if err := p.setupVerify(); err != nil {
		return nil, err
	}
	presignedReq, err := p.stsPresignClient.PresignGetCallerIdentity(p.Context,
		&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	p.Logger.Debugf(2, "presigned URL: %v\n", presignedReq.URL)
	hostPath := p.KeymasterServer + paths.RequestAwsRoleCertificatePath
	body := &bytes.Buffer{}
	body.Write(p.pemPubKey)
	req, err := http.NewRequestWithContext(p.Context, "POST", hostPath, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("claimed-arn", p.roleArn)
	req.Header.Add("presigned-method", presignedReq.Method)
	req.Header.Add("presigned-url", presignedReq.URL)
	resp, err := p.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("got error from call %s, url='%s'\n",
			resp.Status, hostPath)
	}
	return ioutil.ReadAll(resp.Body)
}

// Returns certificate PEM block, TLS certificate and error.
func (p *Params) getRoleCertificateTLS() ([]byte, *tls.Certificate, error) {
	certPEM, err := p.getRoleCertificate()
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("unable to decode certificate PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("invalid certificate type: %s", block.Type)
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return certPEM,
		&tls.Certificate{
			Certificate: [][]byte{block.Bytes},
			PrivateKey:  p.Signer,
			Leaf:        x509Cert,
		},
		nil
}

func (p *Params) setupVerify() error {
	if p.isSetup {
		return nil
	}
	if p.KeymasterServer == "" {
		return fmt.Errorf("no keymaster server specified")
	}
	if p.Logger == nil {
		return fmt.Errorf("no logger specified")
	}
	if p.Context == nil {
		p.Context = context.TODO()
	}
	if p.HttpClient == nil {
		p.HttpClient = http.DefaultClient
	}
	if p.Signer == nil {
		signer, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
		if err != nil {
			return err
		}
		p.Signer = signer
	}
	derPubKey, err := x509.MarshalPKIXPublicKey(p.Signer.Public())
	if err != nil {
		return err
	}
	p.derPubKey = derPubKey
	p.pemPubKey = pem.EncodeToMemory(&pem.Block{
		Bytes: p.derPubKey,
		Type:  "PUBLIC KEY",
	})
	awsConfig, err := config.LoadDefaultConfig(p.Context,
		config.WithEC2IMDSRegion())
	if err != nil {
		return err
	}
	p.awsConfig = awsConfig
	p.stsClient = sts.NewFromConfig(awsConfig)
	p.stsPresignClient = sts.NewPresignClient(p.stsClient)
	idOutput, err := p.stsClient.GetCallerIdentity(p.Context,
		&sts.GetCallerIdentityInput{})
	if err != nil {
		return err
	}
	p.Logger.Debugf(0, "Account: %s, ARN: %s, UserId: %s\n",
		*idOutput.Account, *idOutput.Arn, *idOutput.UserId)
	parsedArn, err := parseArn(*idOutput.Arn)
	if err != nil {
		return err
	}
	p.roleArn = parsedArn.String()
	p.isSetup = true
	return nil
}
