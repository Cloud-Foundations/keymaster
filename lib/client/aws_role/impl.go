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
	"time"

	"github.com/Cloud-Foundations/golib/pkg/awsutil/presignauth/presigner"

	"github.com/Cloud-Foundations/keymaster/lib/paths"
)

const rsaKeySize = 2048

func newManager(p Params) (*Manager, error) {
	certPEM, certTLS, err := p.getRoleCertificateTLS()
	if err != nil {
		return nil, err
	}
	p.Logger.Printf("got AWS Role certificate for: %s\n",
		p.presigner.GetCallerARN())
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
		if m.params.MaxSleepDuration > time.Second && duration > m.params.MaxSleepDuration {
			duration = m.params.MaxSleepDuration
		}
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
			m.params.presigner.GetCallerARN())
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
	presignedReq, err := p.presigner.PresignGetCallerIdentity(p.Context)
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
	req.Header.Add("claimed-arn", p.presigner.GetCallerARN().String())
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
	p.presigner, err = presigner.New(presigner.Params{
		AwsConfig:        p.AwsConfig,
		Logger:           p.Logger,
		StsClient:        p.StsClient,
		StsPresignClient: p.StsPresignClient,
	})
	if err != nil {
		return err
	}
	p.isSetup = true
	return nil
}
