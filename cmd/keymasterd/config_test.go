package main

import (
	"bufio"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
)

// openssl genpkey  -algorithm ED25519 -out key.pem
const pkcs8Ed25519PrivateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHoHbl2RwHwmyWtXVLroUZEI+d/SqL3RKmECM5P7o7D5
-----END PRIVATE KEY-----`

func TestGenerateNewConfigInternal(t *testing.T) {
	t.Logf("hello")
	dir, err := ioutil.TempDir("", "config_testing")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	configFilename := filepath.Join(dir, "config-test.yml")

	readerContent := dir + "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
	baseReader := strings.NewReader(readerContent)
	reader := bufio.NewReader(baseReader)
	passphrase := []byte("passphrase")
	err = generateNewConfigInternal(reader, configFilename, 2048, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	datapath := filepath.Join(dir, "var/lib/keymaster")
	err = os.MkdirAll(datapath, 0750)
	if err != nil {
		t.Fatal(err)
	}
	// AND not try to load
	_, err = loadVerifyConfigFile(configFilename, testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}

	// TODO: test decrypt file
}

func TestLoadSignersFromPemData(t *testing.T) {
	//testSignerPrivateKey
	state := RuntimeState{logger: testlogger.New(t)}
	//expect success just signer key
	err := state.loadSignersFromPemData([]byte(testSignerPrivateKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = state.loadSignersFromPemData([]byte(testSignerPrivateKey), []byte(pkcs8Ed25519PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	// now failure ... the signer is ed25519 which is not compatible with x509
	err = state.loadSignersFromPemData([]byte(pkcs8Ed25519PrivateKey), []byte(pkcs8Ed25519PrivateKey))
	if err == nil {
		t.Fatalf("Should have failed because signer is NOT a compatible key")
	}
	// another failure, both are RSA
	err = state.loadSignersFromPemData([]byte(testSignerPrivateKey), []byte(testSignerPrivateKey))
	if err == nil {
		t.Fatalf("Should have failed because passed edsigner is RSA not ed25519")
	}
	// another failure, signer is not even pem
	err = state.loadSignersFromPemData([]byte("hello"), []byte(testSignerPrivateKey))
	if err == nil {
		t.Fatalf("Should have failed because passed sginer data is not even pem")
	}
	err = state.loadSignersFromPemData([]byte(testSignerPrivateKey), []byte("hello"))
	if err == nil {
		t.Fatalf("Should have failed because signer ed signer is not even pem")
	}

}
