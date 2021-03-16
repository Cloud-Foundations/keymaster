package util

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/client/net"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/publicsuffix"
)

const rsaKeySize = 2048

func getUserCreds(userName string) (password []byte, err error) {
	fmt.Printf("Password for %s: ", userName)
	password, err = gopass.GetPasswd()
	if err != nil {
		return nil, err
		// Handle gopass.ErrInterrupted or getch() read error
	}
	return password, nil
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
