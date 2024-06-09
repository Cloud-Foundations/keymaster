package eventnotifier

import (
	"net/http"
	"sync"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/proto/eventmon"
)

type EventNotifier struct {
	logger log.DebugLogger
	mutex  sync.Mutex
	// Protected by lock.
	transmitChannels map[chan<- eventmon.EventV0]chan<- eventmon.EventV0
}

func New(logger log.DebugLogger) *EventNotifier {
	return newEventNotifier(logger)
}

func (n *EventNotifier) PublishAuthEvent(authType, username string) {
	n.publishAuthEvent(authType, username)
}

func (n *EventNotifier) PublishServiceProviderLoginEvent(url, username string) {
	n.publishServiceProviderLoginEvent(url, username)
}

func (n *EventNotifier) PublishSSH(cert []byte) {
	n.publishCert(eventmon.EventTypeSSHCert, cert)
}

func (n *EventNotifier) PublishWebLoginEvent(username string) {
	n.publishWebLoginEvent(username)
}

func (n *EventNotifier) PublishVIPAuthEvent(vipAuthType, username string) {
	n.publishVIPAuthEvent(vipAuthType, username)
}

func (n *EventNotifier) PublishX509(cert []byte) {
	n.publishCert(eventmon.EventTypeX509Cert, cert)
}

func (n *EventNotifier) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	n.serveHTTP(w, req)
}
