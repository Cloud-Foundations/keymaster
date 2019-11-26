package eventrecorder

import (
	"crypto/x509"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/log"
	"golang.org/x/crypto/ssh"
)

const (
	AuthTypeNone = iota
	AuthTypePassword
	AuthTypeSymantecVIP
	AuthTypeU2F
)

const (
	VIPAuthTypeOTP = iota
	VIPAuthTypePush
)

type AuthInfo struct {
	AuthType    uint
	Username    string
	VIPAuthType uint8
}

type Events struct {
	ComputeTime time.Duration
	Events      EventsMap
}

type EventsMap map[string][]EventType // Key: username.

type eventsListType struct {
	newest *eventType
	oldest *eventType
}

type EventType struct {
	AuthType           uint
	CreateTime         uint64 // Seconds since Epoch.
	LifetimeSeconds    uint32
	ServiceProviderUrl string
	Ssh                bool
	WebLogin           bool
	X509               bool
	VIPAuthType        uint8
}

type eventType struct {
	EventType
	newer *eventType
	older *eventType
}

type EventRecorder struct {
	AuthChannel                 chan<- *AuthInfo
	RequestEventsChannel        chan<- chan<- Events
	ServiceProviderLoginChannel chan<- *SPLoginInfo
	SshCertChannel              chan<- *ssh.Certificate
	WebLoginChannel             chan<- string
	X509CertChannel             chan<- *x509.Certificate
	filename                    string
	logger                      log.Logger
	eventsMap                   map[string]*eventsListType // Key: username.
}

type SPLoginInfo struct {
	URL      string
	Username string
}

func New(filename string, logger log.Logger) (*EventRecorder, error) {
	return newEventRecorder(filename, logger)
}
