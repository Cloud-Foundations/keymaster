package monitord

import (
	"crypto/x509"
	"io"
	"sync"

	"github.com/Cloud-Foundations/Dominator/lib/log"
	"golang.org/x/crypto/ssh"
)

type AuthInfo struct {
	AuthType    string
	Username    string
	VIPAuthType string
}

type SPLoginInfo struct {
	URL      string
	Username string
}

type Monitor struct {
	keymasterServerHostname string
	keymasterServerPortNum  uint
	closers                 map[string]chan<- struct{} // [addr]close notifier.
	// Transmit side channels (private).
	authChannel                 chan<- AuthInfo
	serviceProviderLoginChannel chan<- SPLoginInfo
	sshRawCertChannel           chan<- []byte
	sshCertChannel              chan<- *ssh.Certificate
	webLoginChannel             chan<- string
	x509RawCertChannel          chan<- []byte
	x509CertChannel             chan<- *x509.Certificate
	// Receive side channels (public).
	AuthChannel                 <-chan AuthInfo
	ServiceProviderLoginChannel <-chan SPLoginInfo
	SshRawCertChannel           <-chan []byte
	SshCertChannel              <-chan *ssh.Certificate
	WebLoginChannel             <-chan string
	X509RawCertChannel          <-chan []byte
	X509CertChannel             <-chan *x509.Certificate
	mutex                       sync.RWMutex     // Lock all below.
	keymasterStatus             map[string]error // Key: IP address.
}

func New(keymasterServerHostname string, keymasterServerPortNum uint,
	logger log.Logger) (*Monitor, error) {
	return newMonitor(keymasterServerHostname, keymasterServerPortNum, logger)
}

func (m *Monitor) WriteHtml(writer io.Writer) {
	m.writeHtml(writer)
}
