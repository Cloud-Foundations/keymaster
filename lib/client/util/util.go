package util

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/client/net"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/term"
)

const rsaKeySize = 2048

const maxPasswordLength = 512

func getUserCreds(userName string) (password []byte, err error) {
	fmt.Printf("Password for %s: ", userName)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		password, err = term.ReadPassword(int(os.Stdin.Fd()))

		// Always print newline, even on error
		fmt.Println()

		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
	} else {
		// Read password from stdin without terminal operations
		var pass []byte
		reader := bufio.NewReader(os.Stdin)

		for counter := 0; counter <= maxPasswordLength; counter++ {
			b, err := reader.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("failed to read password: %w", err)
			}

			switch b {
			case 0: // NULL byte - ignore
				continue
			case 127, 8: // Backspace
				if len(pass) > 0 {
					pass = pass[:len(pass)-1]
				}
				continue // Skip the current iteration after removing character
			case 13, 10: // Enter/newline
				password = pass
				return password, nil
			case 3: // Ctrl-C
				return nil, errors.New("interrupted")
			default:
				pass = append(pass, b)
			}
		}

		// If we get here, we've exceeded maxPasswordLength
		return nil, errors.New("maximum length exceeded")
	}

	// Check password length
	if len(password) > maxPasswordLength {
		return nil, errors.New("maximum length exceeded")
	}

	return password, nil
}

func getUserNameAndHomeDir() (string, string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("cannot get current user info")
	}
	userName := usr.Username
	if runtime.GOOS == "windows" {
		splitName := strings.Split(userName, "\\")
		if len(splitName) == 2 {
			userName = strings.ToLower(splitName[1])
		}
	}
	homeDir := os.Getenv("HOME")
	if homeDir != "" {
		return userName, homeDir, nil
	}
	return userName, usr.HomeDir, nil
}

// will encode key as pkcs8.... camilo needs to test for interop
func writeSSHKeyPairToFile(privateKeyPath string, identity string,
	privateKey crypto.Signer, logger log.Logger) (string, error) {

	var encodedSigner []byte
	var err error
	var pemBlockType = "PRIVATE KEY"
	// For Interoperatibility we want to keep using pkcs1 until we can verify pkc8 is good
	switch v := privateKey.(type) {
	case *rsa.PrivateKey:
		pemBlockType = "RSA PRIVATE KEY"
		encodedSigner = x509.MarshalPKCS1PrivateKey(v)
	default:
		encodedSigner, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return "", err
		}
	}
	err = ioutil.WriteFile(
		privateKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: pemBlockType, Bytes: encodedSigner}),
		0600)
	if err != nil {
		logger.Printf("Failed to save privkey")
	}
	// generate and write public key
	pub, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return "", err
	}
	marshaledPubKeyBytes := ssh.MarshalAuthorizedKey(pub)
	marshaledPubKeyBytes = bytes.TrimRight(marshaledPubKeyBytes, "\r\n")
	var pubKeyBuffer bytes.Buffer
	_, err = pubKeyBuffer.Write(marshaledPubKeyBytes)
	if err != nil {
		return "", err
	}
	_, err = pubKeyBuffer.Write([]byte(" " + identity + "\n"))
	if err != nil {
		return "", err
	}
	pubKeyPath := privateKeyPath + ".pub"
	return pubKeyPath, ioutil.WriteFile(pubKeyPath, pubKeyBuffer.Bytes(), 0644)
}

// mostly comes from: http://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key
func genKeyPair(
	privateKeyPath string, identity string, logger log.Logger) (
	crypto.Signer, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, "", err
	}
	pubKeyPath, err := writeSSHKeyPairToFile(privateKeyPath, identity, privateKey, logger)
	if err != nil {
		return nil, "", err
	}
	return privateKey, pubKeyPath, nil
}

func getHttpClient(tlsConfig *tls.Config,
	dialer net.Dialer) (*http.Client, error) {
	clientTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext:     dialer.DialContext,
	}

	// proxy env variables in ascending order of preference, lower case 'http_proxy' dominates
	// just like curl
	proxyEnvVariables := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy"}
	for _, proxyVar := range proxyEnvVariables {
		httpProxy, err := getParseURLEnvVariable(proxyVar)
		if err == nil && httpProxy != nil {
			clientTransport.Proxy = http.ProxyURL(httpProxy)
		}
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	// TODO: change timeout const for a flag
	client := &http.Client{Transport: clientTransport, Jar: jar, Timeout: 25 * time.Second}
	return client, nil
}

func getParseURLEnvVariable(name string) (*url.URL, error) {
	envVariable := os.Getenv(name)
	if len(envVariable) < 1 {
		return nil, nil
	}
	envUrl, err := url.Parse(envVariable)
	if err != nil {
		return nil, err
	}

	return envUrl, nil
}
