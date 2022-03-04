package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
	"github.com/Cloud-Foundations/keymaster/lib/client/config"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(localhostCertPem), []byte(localhostKeyPem))
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS11,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
	}, nil
}

const localHttpsTarget = "https://localhost:19443/"

var testAllowedCertBackends = []string{proto.AuthTypePassword, proto.AuthTypeU2F}

func handler(w http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{Name: "somename", Value: "somevalue"}
	http.SetCookie(w, &authCookie)
	switch r.URL.Path {
	case proto.LoginPath:
		loginResponse := proto.LoginResponse{Message: "success",
			CertAuthBackend: testAllowedCertBackends}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)

	default:
		fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	}
}

func init() {
	tlsConfig, _ := getTLSconfig()
	//_, _ = tls.Listen("tcp", ":11443", config)
	srv := &http.Server{
		Addr:      "127.0.0.1:19443",
		TLSConfig: tlsConfig,
	}
	http.HandleFunc("/", handler)
	go srv.ListenAndServeTLS("", "")
	// On single core systems we needed to ensure that the server is started before
	// we create other testing goroutines. By sleeping we yield the cpu and allow
	// ListenAndServe to progress
	time.Sleep(20 * time.Millisecond)
}

func TestGetCertFromTargetUrlsSuccessOneURL(t *testing.T) {
	_, _, err := getUserNameAndHomeDir(testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetHttpClient(t *testing.T) {
	client, err := getHttpClient(nil, testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal(err)
	}

	//now with
}

func TestBackgroundConnectToAnyKeymasterServer(t *testing.T) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	logger := testlogger.New(t)

	*roundRobinDialer = false
	for i := 0; i < 2; i++ {
		client, err := getHttpClient(certPool, logger)
		if err != nil {
			t.Fatal(err)
		}
		err = backgroundConnectToAnyKeymasterServer([]string{localHttpsTarget}, client, logger)
		if err != nil {
			t.Fatal(err)
		}
		//now with fail:
		client2, err := getHttpClient(nil, logger)
		err = backgroundConnectToAnyKeymasterServer([]string{localHttpsTarget}, client2, logger)
		if err == nil {
			t.Fatal("should have failed")
		}
		*roundRobinDialer = true
	}

}

func pipeToStdin(s string) (int, error) {
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		fmt.Println("Error getting os pipes:", err)
		os.Exit(1)
	}
	os.Stdin = pipeReader
	w, err := pipeWriter.WriteString(s)
	pipeWriter.Close()
	return w, err
}

func TestMaybeGetRootCas(t *testing.T) {
	logger := testlogger.New(t)
	shouldbeNil, err := maybeGetRootCas("", logger)
	if err != nil {
		t.Fatal(err)
	}
	if shouldbeNil != nil {
		t.Fatal("should be nil and it is not")
	}

	tmpfile, err := ioutil.TempFile("", "userdb_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err = tmpfile.Write([]byte(rootCAPem)); err != nil {
		t.Fatal(err)
	}
	if err = tmpfile.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = maybeGetRootCas(tmpfile.Name(), logger)
	if err != nil {
		t.Fatal(err)
	}

}

func TestMost(t *testing.T) {

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	logger := testlogger.New(t)
	client, err := getHttpClient(certPool, logger)
	if err != nil {
		t.Fatal(err)
	}
	userName, homeDir, err := getUserNameAndHomeDir(logger)
	if err != nil {
		t.Fatal(err)
	}
	tmpdir, err := ioutil.TempDir("", "keymaster"+userName)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	homeDir = tmpdir
	appConfig := config.AppConfigFile{
		Base: config.BaseConfig{
			Gen_Cert_URLS: localHttpsTarget,
			FilePrefix:    "test"}}

	_, err = pipeToStdin("password\n")
	if err != nil {
		t.Fatal(err)
	}

	FilePrefix = "test"
	oldSSHSock, ok := os.LookupEnv("SSH_AUTH_SOCK")
	if ok {
		os.Unsetenv("SSH_AUTH_SOCK")
		defer os.Setenv("SSH_AUTH_SOCK", oldSSHSock)
	}
	setupCerts(
		userName,
		homeDir,
		appConfig,
		client,
		logger)

}

func goCertToFileString(c ssh.Certificate, username string) (string, error) {
	certBytes := c.Marshal()
	encoded := base64.StdEncoding.EncodeToString(certBytes)
	fileComment := "/tmp/" + username + "-" + c.SignatureKey.Type() + "-cert.pub"
	return c.Type() + " " + encoded + " " + fileComment, nil
}

func TestInsertSSHCertIntoAgentORWriteToFilesystem(t *testing.T) {
	//step 1: generate
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := ssh.Certificate{
		Key:             sshPublic,
		ValidPrincipals: []string{"username"},
		ValidAfter:      uint64(time.Now().Unix()) - 10,
		ValidBefore:     uint64(time.Now().Unix()) + 10,
	}
	sshSigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	err = cert.SignCert(rand.Reader, sshSigner)
	if err != nil {
		t.Fatal(err)
	}
	certString, err := goCertToFileString(cert, "username")
	if err != nil {
		t.Fatal(err)
	}
	// This test needs a running agent... and remote windows
	// builders do NOT have this... thus we need to abort this test
	// until we have a way to NOT timeout on missing agent in
	// windows
	if runtime.GOOS == "windows" {
		return
	}

	/////////Now actually do the work
	oldSSHSock, ok := os.LookupEnv("SSH_AUTH_SOCK")
	if ok {
		os.Unsetenv("SSH_AUTH_SOCK")
		defer os.Setenv("SSH_AUTH_SOCK", oldSSHSock)
	}
	tempDir, err := ioutil.TempDir("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir) // clean up
	privateKeyPath := filepath.Join(tempDir, "test")

	err = insertSSHCertIntoAgentORWriteToFilesystem([]byte(certString),
		privateKey,
		"someprefix",
		"username",
		privateKeyPath,
		testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	//now for now we only check that the file exists
	_, err = os.Stat(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(privateKeyPath)
	// TODO: on linux/macos create agent + unix socket and pass that

}
