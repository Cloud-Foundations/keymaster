package htpassword

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/authutil"
)

func newAuthenticator(filename string,
	logger log.DebugLogger) (*PasswordAuthenticator, error) {
	if fi, err := os.Stat(filename); err != nil {
		return nil, err
	} else if fi.Mode()&os.ModeType != 0 {
		return nil, fmt.Errorf("%s is not a regular file", filename)
	}
	return &PasswordAuthenticator{
		filename: filename,
		logger:   logger,
	}, nil
}

func (pa *PasswordAuthenticator) passwordAuthenticate(username string,
	password []byte) (bool, error) {
	pa.logger.Debugf(3, "checking %s in htpassword file\n", username)
	buffer, err := ioutil.ReadFile(pa.filename)
	if err != nil {
		return false, err
	}
	return authutil.CheckHtpasswdUserPassword(username, string(password),
		buffer)
}
