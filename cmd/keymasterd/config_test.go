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
