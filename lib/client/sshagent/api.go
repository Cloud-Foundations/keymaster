package sshagent

import (
	"github.com/Cloud-Foundations/golib/pkg/log"
)

func InsertCertIntoAgent(
	certText []byte,
	privateKey interface{},
	comment string,
	lifeTimeSecs uint32,
	logger log.Logger) error {
	return insertCertIntoAgent(certText, privateKey, comment, lifeTimeSecs, logger)
}
