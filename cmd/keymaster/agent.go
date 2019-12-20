package main

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Cloud-Foundations/Dominator/lib/log"
	"github.com/cviecco/npipe"
)

func connectToDefaultSSHAgentLocation() (net.Conn, error) {
	if runtime.GOOS == "windows" {
		return npipe.Dial(`\\.\pipe\openssh-ssh-agent`)
	}
	// Here we assume that all other os support unix sockets
	socket := os.Getenv("SSH_AUTH_SOCK")
	return net.Dial("unix", socket)
}

func insertCertIntoAgent(
	certText []byte,
	privateKey interface{},
	comment string,
	lifeTimeSecs uint32,
	logger log.Logger) error {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certText)
	if err != nil {
		logger.Println(err)
		return err
	}
	sshCert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("It is not a certificate")
	}
	conn, err := connectToDefaultSSHAgentLocation()
	if err != nil {
		return err
	}
	defer conn.Close()
	agentClient := agent.NewClient(conn)
	keyToAdd := agent.AddedKey{
		PrivateKey:   privateKey,
		Certificate:  sshCert,
		LifetimeSecs: lifeTimeSecs,
		Comment:      comment,
	}
	return agentClient.Add(keyToAdd)
}
