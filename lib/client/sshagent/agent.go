package sshagent

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/npipe"
)

func connectToDefaultSSHAgentLocation() (net.Conn, error) {
	if runtime.GOOS == "windows" {
		return npipe.Dial(`\\.\pipe\openssh-ssh-agent`)
	}
	// Here we assume that all other os support unix sockets
	socket := os.Getenv("SSH_AUTH_SOCK")
	return net.Dial("unix", socket)
}

func deleteDuplicateEntries(comment string, agentClient agent.ExtendedAgent, logger log.DebugLogger) (int, error) {
	keyList, err := agentClient.List()
	if err != nil {
		return 0, err
	}
	deletedCount := 0
	for _, key := range keyList {
		pubKey, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			logger.Debugln(0, err)
			continue
		}
		_, ok := pubKey.(*ssh.Certificate)
		if !ok {
			continue
		}
		if key.Comment != comment {
			continue
		}
		err = agentClient.Remove(pubKey)
		if err != nil {
			return deletedCount, err
		}
		deletedCount++
	}
	return deletedCount, nil
}

func upsertCertIntoAgentConnection(
	certText []byte,
	privateKey interface{},
	comment string,
	lifeTimeSecs uint32,
	confirmBeforeUse bool,
	conn net.Conn,
	logger log.DebugLogger) error {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certText)
	if err != nil {
		logger.Println(err)
		return err
	}
	sshCert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("It is not a certificate")
	}
	keyToAdd := agent.AddedKey{
		PrivateKey:       privateKey,
		Certificate:      sshCert,
		Comment:          comment,
		ConfirmBeforeUse: confirmBeforeUse,
	}
	return withAddedKeyUpsertCertIntoAgentConnection(keyToAdd, conn, logger)
}

func upsertCertIntoAgent(
	certText []byte,
	privateKey interface{},
	comment string,
	lifeTimeSecs uint32,
	confirmBeforeUse bool,
	logger log.DebugLogger) error {
	conn, err := connectToDefaultSSHAgentLocation()
	if err != nil {
		return err
	}
	defer conn.Close()
	return upsertCertIntoAgentConnection(certText, privateKey, comment, lifeTimeSecs, confirmBeforeUse, conn, logger)
}

func withAddedKeyUpsertCertIntoAgentConnection(certToAdd agent.AddedKey, conn net.Conn, logger log.DebugLogger) error {
	if certToAdd.Certificate == nil {
		return fmt.Errorf("Needs a certificate to be added")
	}
	agentClient := agent.NewClient(conn)

	//delete certs in agent with the same comment
	_, err := deleteDuplicateEntries(certToAdd.Comment, agentClient, logger)
	if err != nil {
		logger.Printf("failed during deletion err=%s", err)
		return err
	}
	// NOTE: Current Windows ssh (OpenSSH_for_Windows_7.7p1, LibreSSL 2.6.5)
	// barfs when encountering a lifetime so we only add it for non-windows
	if runtime.GOOS == "windows" {
		certToAdd.LifetimeSecs = 0
		certToAdd.ConfirmBeforeUse = false
	}

	return agentClient.Add(certToAdd)
}

func withAddedKeyUpsertCertIntoAgent(certToAdd agent.AddedKey, logger log.DebugLogger) error {
	conn, err := connectToDefaultSSHAgentLocation()
	if err != nil {
		return err
	}
	defer conn.Close()
	return withAddedKeyUpsertCertIntoAgentConnection(certToAdd, conn, logger)
}
