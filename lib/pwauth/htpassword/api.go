package htpassword

import (
	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/pwauth"
	"github.com/Cloud-Foundations/keymaster/lib/simplestorage"
)

type PasswordAuthenticator struct {
	filename string
	logger   log.DebugLogger
}

// Static interface compatibility check.
var _ = pwauth.PasswordAuthenticator(&PasswordAuthenticator{})

// New creates a new PasswordAuthenticator. The htpassword file used to
// authenticate the user is filename. Log messages are written to logger. A new
// *PasswordAuthenticator is returned if the file exists, else an error is
// returned.
func New(filename string,
	logger log.DebugLogger) (*PasswordAuthenticator, error) {
	return newAuthenticator(filename, logger)
}

// PasswordAuthenticate will authenticate a user using the provided username and
// password.
// It returns true if the user is authenticated, else false (due to either
// invalid username or incorrect password), and an error.
func (pa *PasswordAuthenticator) PasswordAuthenticate(username string,
	password []byte) (bool, error) {
	return pa.passwordAuthenticate(username, password)
}

func (pa *PasswordAuthenticator) UpdateStorage(storage simplestorage.SimpleStore) error {
	return nil
}
