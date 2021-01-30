package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// Ceritifcates built via makefile

func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(localhostCertPem), []byte(localhostKeyPem))
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionSSL30,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
	}, nil
}

func init() {
	//we also make a simple tls listener
	//
	config, _ := getTLSconfig()
	ln, _ := tls.Listen("tcp", "127.0.0.1:10638", config)
	go func(ln net.Listener) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			//log.Printf("Got connection!!!!")
			conn.Write([]byte("hello\n"))
			conn.Close()
		}
	}(ln)
	// On single core systems we needed to ensure that the server is started before
	// we create other testing goroutines. By sleeping we yield the cpu and allow
	// ListenAndServe to progress
	time.Sleep(20 * time.Millisecond)
}

func TestCheckLDAPURLsSuccess(t *testing.T) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	err := checkLDAPURLs("ldaps://localhost:10638", "somename", certPool)
	if err != nil {
		t.Logf("Failed to check ldap url")
		t.Fatal(err)
	}
}

func TestCheckLDAPURLsFailNoValidTargets(t *testing.T) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	err := checkLDAPURLs("ldap://localhost:10638", "somename", certPool)
	if err == nil {
		t.Fatal("Should have failed")
	}
}

func TestCheckLDAPConfigsSuccessBoth(t *testing.T) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	var config AppConfigFile
	config.Ldap.LDAPTargetURLs = "ldaps://localhost:10638"
	config.UserInfo.Ldap.LDAPTargetURLs = "ldaps://localhost:10638"
	checkLDAPConfigs(config, certPool)
}
