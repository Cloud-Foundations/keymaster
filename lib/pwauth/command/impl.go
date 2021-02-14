package command

import (
	"bytes"
	"os/exec"
	"syscall"

	"github.com/Cloud-Foundations/golib/pkg/log"
)

func newAuthenticator(command string, args []string, logger log.Logger) (
	*PasswordAuthenticator, error) {
	command, err := exec.LookPath(command)
	if err != nil {
		return nil, err
	}
	return &PasswordAuthenticator{command, args, logger}, nil
}

func (pa *PasswordAuthenticator) passwordAuthenticate(username string,
	password []byte) (bool, error) {
	args := []string{username}
	args = append(args, pa.args...)
	cmd := exec.Command(pa.command, args...)
	cmd.Stdin = bytes.NewReader(password)
	if _, err := cmd.Output(); err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			if e.Exited() && e.Sys().(syscall.WaitStatus).ExitStatus() == 1 {
				return false, nil
			}
		}
		pa.logger.Println(err)
		return false, err
	}
	return true, nil
}
