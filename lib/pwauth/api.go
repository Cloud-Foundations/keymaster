package pwauth

import (
	"github.com/Cloud-Foundations/keymaster/lib/simplestorage"
)

// PasswordAuthenticator is an interface type that defines how to authenticate a
// user with a username and password.
type PasswordAuthenticator interface {
	// PasswordAuthenticate will authenticate a user using the provided username
	// and password. It returns whether the authentication succeeded and an
	// error.
	PasswordAuthenticate(username string, password []byte) (bool, error)
	UpdateStorage(storage simplestorage.SimpleStore) error
}
