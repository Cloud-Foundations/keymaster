package okta

import (
	"sync"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/simplestorage"
)

// This module implements the PasswordAuthenticator interface and will implement
// a unified 2fa backend interface in some future

type authCacheData struct {
	response OktaApiPrimaryResponseType
	expires  time.Time
}

type PasswordAuthenticator struct {
	authnURL   string
	logger     log.Logger
	mutex      sync.Mutex
	recentAuth map[string]authCacheData
}

type PushResponse int

const (
	PushResponseRejected PushResponse = iota
	PushResponseApproved
	PushResponseWaiting
	PushResonseTimeout
)

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

// VerifyOTP
func (pa *PasswordAuthenticator) ValidateUserOTP(username string, otpValue int) (bool, error) {
	return pa.validateUserOTP(username, otpValue)
}

// Initialize and verify Push
func (pa *PasswordAuthenticator) ValidateUserPush(username string) (PushResponse, error) {
	return pa.validateUserPush(username)
}

// New creates a new public authenticator, but poiting to an explicit authenticator url
func NewPublicTesting(authnURL string, logger log.Logger) (
	*PasswordAuthenticator, error) {
	pa, err := newPublicAuthenticator("example.com", logger)
	if err != nil {
		return pa, err
	}
	pa.authnURL = authnURL
	return pa, nil
}

/*
// SetAuthnURL. For testing only, update the internal authURL so that the backend can be tested
func (pa *PasswordAuthenticator) SetAuthnURL(authnURL string) error {
	pa.authnURL = authnURL
	return nil
}
*/
