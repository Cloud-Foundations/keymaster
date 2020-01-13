package command

import (
	"github.com/Cloud-Foundations/Dominator/lib/log"
	"github.com/Cloud-Foundations/keymaster/lib/simplestorage"
)

type PasswordAuthenticator struct {
	command string
	args    []string
	logger  log.Logger
}

// New creates a new PasswordAuthenticator. The command used to authenticate the
// user is command and args may contain optional arguments to pass after the
// username. Log messages are written to logger. A new *PasswordAuthenticator is
// returned if the command exists, else an error is returned.
// The command should exit with 0 for a successful authentication, 1 if the
// authentication is not successful (bad username/password) and any other value
// if an error occurs.
func New(command string, args []string, logger log.Logger) (
	*PasswordAuthenticator, error) {
	return newAuthenticator(command, args, logger)
}

// PasswordAuthenticate will authenticate a user using the provided username and
// password. The password is provided on the standard input of the
// authentication command.
// It returns true if the user is authenticated, else false (due to either
// invalid username or incorrect password), and an error.
func (pa *PasswordAuthenticator) PasswordAuthenticate(username string,
	password []byte) (bool, error) {
	return pa.passwordAuthenticate(username, password)
}

func (pa *PasswordAuthenticator) UpdateStorage(storage simplestorage.SimpleStore) error {
	return nil
}
