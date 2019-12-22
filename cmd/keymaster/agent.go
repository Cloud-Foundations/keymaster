package main

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Cloud-Foundations/Dominator/lib/log"
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

func deleteDuplicateEntries(comment string, agentClient agent.ExtendedAgent, logger log.Logger) (int, error) {
	keyList, err := agentClient.List()
	if err != nil {
		return 0, err
	}
	deletedCount := 0
	for _, key := range keyList {
		pubKey, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			logger.Println(err)
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

	//delete certs in agent with the same comment
	_, err = deleteDuplicateEntries(comment, agentClient, logger)
	if err != nil {
		logger.Printf("failed during deletion err=%s", err)
		return err
	}

	keyToAdd := agent.AddedKey{
		PrivateKey:  privateKey,
		Certificate: sshCert,
		Comment:     comment,
	}
	// NOTE: Current Windows ssh (OpenSSH_for_Windows_7.7p1, LibreSSL 2.6.5)
	// barfs when encountering a lifetime so we only add it for non-windows
	if runtime.GOOS != "windows" {
		keyToAdd.LifetimeSecs = lifeTimeSecs
	}

	return agentClient.Add(keyToAdd)
}
