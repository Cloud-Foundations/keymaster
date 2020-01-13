package sshagent

import (
	"github.com/Cloud-Foundations/golib/pkg/log"
)

func UpsertCertIntoAgent(
	certText []byte,
	privateKey interface{},
	comment string,
	lifeTimeSecs uint32,
	logger log.Logger) error {
	return upsertCertIntoAgent(certText, privateKey, comment, lifeTimeSecs, logger)
}
