package sshagent

import (
	"golang.org/x/crypto/ssh/agent"
	"net"

	"github.com/Cloud-Foundations/golib/pkg/log"
)

func UpsertCertIntoAgent(
	certText []byte,
	privateKey interface{},
	comment string,
	lifeTimeSecs uint32,
	logger log.DebugLogger) error {
	return upsertCertIntoAgent(certText, privateKey, comment, lifeTimeSecs, false, logger)
}

func UpsertCertIntoAgentConnection(
	certText []byte,
	privateKey interface{},
	comment string,
	lifeTimeSecs uint32,
	confirmBeforeUse bool,
	conn net.Conn,
	logger log.DebugLogger) error {
	return upsertCertIntoAgentConnection(certText, privateKey, comment, lifeTimeSecs, confirmBeforeUse, conn, logger)
}

func WithAddedKeyUpsertCertIntoAgent(certToAdd agent.AddedKey, logger log.DebugLogger) error {
	return withAddedKeyUpsertCertIntoAgent(certToAdd, logger)
}

func WithAddedKeyUpsertCertIntoAgentConnection(certToAdd agent.AddedKey, conn net.Conn, logger log.DebugLogger) error {
	return withAddedKeyUpsertCertIntoAgentConnection(certToAdd, conn, logger)
}
