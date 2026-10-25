package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/Cloud-Foundations/keymaster/lib/client/config"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa/u2f"
	"github.com/Cloud-Foundations/keymaster/lib/client/util"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(localhostCertPem), []byte(localhostKeyPem))
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
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
	userName, homeDir, err := util.GetUserNameAndHomeDir()
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
			Gen_Cert_URLS:    localHttpsTarget,
			PreferredKeyType: "rsa", //TODO move to ecdsa later
			FilePrefix:       "test"}}

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
	sshPublicBytes := ssh.MarshalAuthorizedKey(sshPublic)

	sshSigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	seconds := 10
	certDuration := time.Duration(seconds) * time.Second
	extensions := make(map[string]string)

	certString, _, err := certgen.GenSSHCertFileString("username", string(sshPublicBytes), sshSigner, "km.example.com", certDuration, extensions)

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
		false,
		testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	//now for now we only check that the file exists
	_, err = os.Stat(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(privateKeyPath)

	//t.Logf("certString='%s'", certString)

	// TODO: on linux/macos create agent + unix socket and pass that
	if oldSSHSock != "" && runtime.GOOS == "darwin" {
		//reset the socket
		err = os.Setenv("SSH_AUTH_SOCK", oldSSHSock)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("ssh-add", "-t", "30", privateKeyPath)
		err := cmd.Run()
		if err != nil {
			t.Fatalf("Command finished with error: %v", err)
		}
	}
}

func TestMainSimple(t *testing.T) {
	logger := testlogger.New(t)
	var b bytes.Buffer

	// version
	*printVersion = true
	err := mainWithError(&b, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("versionout='%s'", b.String())
	// TODO: compara out to version string
	*printVersion = false
	b.Reset()

	// checkDevices
	*checkDevices = true
	// As of May 2024, no devices returns an error on checkForDevices
	// Because this will run inside or outside testing infra, we can
	// only check if the error is consistent if any
	checkDevRvalue := u2f.CheckU2FDevices(logger)
	err = mainWithError(&b, logger)
	if err != nil && (err.Error() != checkDevRvalue.Error()) {
		t.Fatalf("manual an executed error mismatch mainerr=%s; chdevDerr=%s", err, checkDevRvalue)
	}
	*checkDevices = false
	b.Reset()

}

func TestPasswordStdinWithU2F(t *testing.T) {
	logger := testlogger.New(t)
	var b bytes.Buffer

	// Test case 1: password-stdin with U2F disabled should fail
	*passwordStdin = true
	twofa.SetNoU2F(true)
	twofa.SetNoTOTP(false)
	twofa.SetNoVIPAccess(false)

	err := mainWithError(&b, logger)
	if err == nil {
		t.Fatal("Expected error when using password-stdin with U2F disabled")
	}
	if err.Error() != "U2F must be enabled when using --password-stdin" {
		t.Fatalf("Unexpected error message: %s", err.Error())
	}

	// Test case 2: password-stdin with U2F enabled should enforce TOTP and VIPAccess disabled
	twofa.SetNoU2F(false)
	twofa.SetNoTOTP(false)
	twofa.SetNoVIPAccess(false)

	// Pipe a password to stdin for the test
	_, err = pipeToStdin("testpassword\n")
	if err != nil {
		t.Fatal(err)
	}

	err = mainWithError(&b, logger)
	if err != nil {
		// The error should be from trying to connect to the server, not from the U2F validation
		if err.Error() == "U2F must be enabled when using --password-stdin" {
			t.Fatal("U2F validation failed when it should have passed")
		}
	}

	// Verify TOTP and VIPAccess were disabled
	if !twofa.GetNoTOTP() {
		t.Error("TOTP should be disabled when using password-stdin")
	}
	if !twofa.GetNoVIPAccess() {
		t.Error("VIPAccess should be disabled when using password-stdin")
	}

	// Reset the flags
	*passwordStdin = false
	twofa.SetNoU2F(false)
	twofa.SetNoTOTP(false)
	twofa.SetNoVIPAccess(false)
}
