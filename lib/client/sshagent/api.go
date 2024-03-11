package sshagent

import (
	"golang.org/x/crypto/ssh/agent"

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

func WithAddedKeyUpsertCertIntoAgent(certToAdd agent.AddedKey, logger log.DebugLogger) error {
	return withAddedKeyUpsertCertIntoAgent(certToAdd, logger)
}
