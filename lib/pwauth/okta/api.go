package okta

import (
	"github.com/Cloud-Foundations/Dominator/lib/log"
	"github.com/Cloud-Foundations/keymaster/lib/simplestorage"
)

type PasswordAuthenticator struct {
	authnURL string
	logger   log.Logger
}

// New creates a new PasswordAuthenticator using Okta as the backend. The Okta
// Public Application API is used, so rate limits apply.
// The Okta domain to check must be given by oktaDomain.
// Log messages are written to logger. A new *PasswordAuthenticator is returned.
func NewPublic(oktaDomain string, logger log.Logger) (
	*PasswordAuthenticator, error) {
	return newPublicAuthenticator(oktaDomain, logger)
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
