package util

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
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
	defer os.Remove(tmpfile.Name() + ".pub") // clean up
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
	userName, homeDir, err := GetUserNameAndHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if len(userName) < 1 {
		t.Fatal("invalid userName")
	}
	if len(homeDir) < 1 {
		t.Fatal("invalid homeDir")
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

func TestGetUserCreds(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
		errMsg  string
	}{
		{
			name:  "basic password",
			input: "password\n",
			want:  "password",
		},
		{
			name:  "password with backspace",
			input: "passworrd\x08\x08d\n", // \x08 is backspace
			want:  "password",
		},
		{
			name:  "ignore null bytes",
			input: "pass\x00word\n",
			want:  "password",
		},
		{
			name:    "ctrl-c interruption",
			input:   "pass\x03word\n",
			wantErr: true,
			errMsg:  "interrupted",
		},
		{
			name:    "max length exceeded",
			input:   string(make([]byte, maxPasswordLength+1)) + "\n",
			wantErr: true,
			errMsg:  "maximum length exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pipeToStdin(tt.input)
			if err != nil {
				t.Fatal(err)
			}

			password, err := getUserCreds("username", false)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(password) != tt.want {
				t.Errorf("got password %q, want %q", string(password), tt.want)
			}
		})
	}
}

func TestGetUserCredsFromStdin(t *testing.T) {
	// Save old stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	// Create a pipe
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	// Write test password to pipe
	testPassword := "test-password-123\n"
	go func() {
		w.Write([]byte(testPassword))
		w.Close()
	}()

	password, err := getUserCreds("username", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(password) != "test-password-123" {
		t.Errorf("got password %q, want %q", string(password), "test-password-123")
	}
}

// ------------WARN-------- Next name copied from https://github.com/howeyc/gopass/blob/master/pass_test.go for using
//
//	gopass checks
func TestPipe(t *testing.T) {
	_, err := pipeToStdin("password\n")
	if err != nil {
		t.Fatal(err)
	}
	password, err := GetUserCreds("userame", false)
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
