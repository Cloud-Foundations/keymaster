package util

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"testing"

	"github.com/Cloud-Foundations/Dominator/lib/log/testlogger"
	"github.com/Cloud-Foundations/keymaster/lib/certgen"
)

func TestGenKeyPairSuccess(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "test_genKeyPair_")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	_, _, err = GenKeyPair(tmpfile.Name(), "test", testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	fileBytes, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	_, err = certgen.GetSignerFromPEMBytes(fileBytes)
	if err != nil {
		t.Fatal(err)
	}
	//TODO: verify written signer matches our signer.
}

func TestGenKeyPairFailNoPerms(t *testing.T) {
	_, _, err := GenKeyPair("/proc/something", "test", testlogger.New(t))
	if err == nil {
		t.Logf("Should have failed")
		t.Fatal(err)
	}
}

func TestGetUserHomeDirSuccess(t *testing.T) {
	usr, err := user.Current()
	if err != nil {
		t.Logf("cannot get current user info")
		t.Fatal(err)
	}
	homeDir, err := GetUserHomeDir(usr)
	if err != nil {
		t.Fatal(err)
	}
	if len(homeDir) < 1 {
		t.Fatal("invalid homedir")

	}
}

func TestGetParseURLEnvVariable(t *testing.T) {
	testName := "TEST_ENV_KEYMASTER_11111"
	os.Setenv(testName, "http://localhost:12345")
	val, err := getParseURLEnvVariable(testName)
	if err != nil {
		t.Fatal(err)
	}
	if val == nil {
		t.Fatal("Should have found value")
	}

	//Not a URL
	/*
		        os.Setenv(testName, "")
				        if err == nil {
								            t.Fatal("should have failed to parse")
											        }
	*/

	//Unexistent
	// TODO: check for the return error
	val, _ = getParseURLEnvVariable("Foobar")
	if val != nil {
		t.Fatal("SHOULD not have found anything ")
	}
	//

}

// ------------WARN-------- Next name copied from https://github.com/howeyc/gopass/blob/master/pass_test.go for using
//  gopass checks
func TestPipe(t *testing.T) {
	_, err := pipeToStdin("password\n")
	if err != nil {
		t.Fatal(err)
	}
	password, err := GetUserCreds("userame")
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "password" {
		t.Fatal("password Does NOT match")
	}

}

// ------------WARN--------------
// THE next two functions are litierly copied from: https://github.com/howeyc/gopass/blob/master/pass_test.go
// pipeToStdin pipes the given string onto os.Stdin by replacing it with an
// os.Pipe.  The write end of the pipe is closed so that EOF is read after the
// final byte.
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

func TestGetHttpClientMinimal(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	_, err := GetHttpClient(tlsConfig, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}

}
