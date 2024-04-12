package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Cloud-Foundations/Dominator/lib/log/cmdlogger"
	"github.com/Cloud-Foundations/Dominator/lib/net/rrdialer"
	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/client/aws_role"
	"github.com/Cloud-Foundations/keymaster/lib/client/config"
	libnet "github.com/Cloud-Foundations/keymaster/lib/client/net"
	"github.com/Cloud-Foundations/keymaster/lib/client/sshagent"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa/u2f"
	"github.com/Cloud-Foundations/keymaster/lib/client/util"
	"github.com/Cloud-Foundations/keymaster/lib/client/webauth"
)

const (
	DefaultSSHKeysLocation = "/.ssh/"
	DefaultTLSKeysLocation = "/.ssl/"
	keymasterSubdir        = ".keymaster"
)

const userAgentAppName = "keymaster"
const defaultVersionNumber = "No version provided"

var (
	// Must be a global variable in the data segment so that the build
	// process can inject the version number on the fly when building the
	// binary. Use only from the Usage() function.
	Version         = defaultVersionNumber
	userAgentString = userAgentAppName
)

var (
	configFilename = flag.String("config",
		filepath.Join(getUserHomeDir(), keymasterSubdir, "client_config.yml"),
		"The filename of the configuration")
	rootCAFilename = flag.String("rootCAFilename", "",
		"(optional) name for using non OS root CA to verify TLS connections")
	configHost = flag.String("configHost", "",
		"Get a bootstrap config from this host")
	cliUsername  = flag.String("username", "", "username for keymaster")
	checkDevices = flag.Bool("checkDevices", false,
		"CheckU2F devices in your system")
	cliFilePrefix = flag.String("fileprefix", "",
		"Prefix for the output files")
	roundRobinDialer = flag.Bool("roundRobinDialer", false,
		"If true, use the smart round-robin dialer")
	webauthBrowser = flag.String("webauthBrowser", "",
		"Browser command to use for webauth")

	FilePrefix = "keymaster"
)

func getUserHomeDir() string {
	_, homeDir, err := util.GetUserNameAndHomeDir()
	if err != nil {
		panic(err)
	}
	return homeDir
}

func maybeGetRootCas(rootCAFilename string, logger log.Logger) (*x509.CertPool, error) {
	var rootCAs *x509.CertPool
	if len(rootCAFilename) > 1 {
		caData, err := ioutil.ReadFile(rootCAFilename)
		if err != nil {
			logger.Printf("Failed to read caFilename")
			return nil, err
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("cannot append file data")
		}

	}
	return rootCAs, nil
}

func loadConfigFile(client *http.Client, logger log.Logger) (
	configContents config.AppConfigFile) {
	configPath, _ := filepath.Split(*configFilename)

	err := os.MkdirAll(configPath, 0755)
	if err != nil {
		logger.Fatal(err)
	}

	if len(*configHost) > 1 {
		err = config.GetConfigFromHost(*configFilename, *configHost,
			client, logger)
		if err != nil {
			logger.Fatal(err)
		}
	} else if len(defaultConfigHost) > 1 { // if there is a configHost AND there is NO config file, create one
		if _, err := os.Stat(*configFilename); os.IsNotExist(err) {
			err = config.GetConfigFromHost(
				*configFilename, defaultConfigHost, client, logger)
			if err != nil {
				logger.Fatal(err)
			}
		}
	}

	configContents, err = config.LoadVerifyConfigFile(*configFilename)
	if err != nil {
		logger.Fatal(err)
	}
	return
}

func preConnectToHost(baseUrl string, client *http.Client, logger log.DebugLogger) error {
	response, err := client.Get(baseUrl)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	//we have to consume the contents of the body in order to keep the connection open
	_, err = ioutil.ReadAll(response.Body)
	if err != nil {
		logger.Debugf(1, "Error reading http responseBody err: %s\n", err)
		return err
	}
	if response.StatusCode >= 300 {
		logger.Debugf(1, "bad response code on pre-connect status=%d", response.StatusCode)
		return err
	}
	logger.Debugf(3, "Success pre-connecting to: '%s'\n", baseUrl)
	if response.TLS != nil {
		logger.Debugf(3, "Preconnect is https")
		for chainIndex, chainList := range response.TLS.VerifiedChains {
			for index, cert := range chainList {
				logger.Debugf(3, "Pre-connect VerifiedChain[%d]Subject[%d] = %s",
					chainIndex, index, cert.Subject.String())
			}
		}
	}
	return nil
}

func backgroundConnectToAnyKeymasterServer(targetUrls []string, client *http.Client, logger log.DebugLogger) error {
	c := make(chan error, len(targetUrls))
	for _, baseUrl := range targetUrls {
		go func(c chan error, baseUrl string, client *http.Client, logger log.DebugLogger) {
			c <- preConnectToHost(baseUrl, client, logger)
		}(c, baseUrl, client, logger)

	}
	var errorList []error
	for i := 0; i < len(targetUrls); i++ {
		err := <-c
		if err != nil {
			logger.Debugf(1, "Debug: Error connecting err=%s", err)
			errorList = append(errorList, err)
			continue
		}
		return nil
	}
	for _, capturedErr := range errorList {
		logger.Printf("Error connecting err=%s", capturedErr)
	}
	return fmt.Errorf("Cannot connect to any keymaster Server")
}

const rsaKeySize = 2048

func generateAwsRoleCert(homeDir string,
	configContents config.AppConfigFile,
	client *http.Client,
	logger log.DebugLogger) error {
	signers := makeSigners()
	// Initialise the client connection.
	targetURLs := strings.Split(configContents.Base.Gen_Cert_URLS, ",")
	err := backgroundConnectToAnyKeymasterServer(targetURLs, client, logger)
	if err != nil {
		return err
	}
	if err := makeDirs(homeDir); err != nil {
		return err
	}
	tlsKeyPath := filepath.Join(homeDir, DefaultTLSKeysLocation, FilePrefix)
	if err := signers.Wait(); err != nil {
		return err
	}
	manager, err := aws_role.NewManager(aws_role.Params{
		KeymasterServer: targetURLs[0],
		Logger:          logger,
		HttpClient:      client,
		Signer:          signers.X509Rsa,
	})
	if err != nil {
		return err
	}
	encodedx509Signer, err := x509.MarshalPKCS8PrivateKey(signers.X509Rsa)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(
		tlsKeyPath+".key",
		pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: encodedx509Signer}),
		0600)
	if err != nil {
		return err
	}
	x509CertPath := tlsKeyPath + ".cert"
	certPEM, _, err := manager.GetRoleCertificate()
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(x509CertPath, certPEM, 0644); err != nil {
		return errors.New("Could not write ssh cert")
	}
	for {
		logger.Println("starting loop waiting for certificate refreshes")
		manager.WaitForRefresh()
		certPEM, _, err := manager.GetRoleCertificate()
		if err != nil {
			return err
		}
		tempPath := x509CertPath + "~"
		err = ioutil.WriteFile(tempPath, certPEM, 0644)
		if err != nil {
			return errors.New("Could not write ssh cert")
		}
		defer os.Remove(tempPath)
		return os.Rename(tempPath, x509CertPath)

	}
	return nil
}

// Beware, this function has inverted path.... at the beggining
func insertSSHCertIntoAgentORWriteToFilesystem(certText []byte,
	signer interface{},
	filePrefix string,
	userName string,
	privateKeyPath string,
	confirmBeforeUse bool,
	logger log.DebugLogger) (err error) {

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certText)
	if err != nil {
		logger.Println(err)
		return err
	}
	sshCert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("It is not a certificate")
	}
	comment := filePrefix + "-" + userName
	keyToAdd := agent.AddedKey{
		PrivateKey:       signer,
		Certificate:      sshCert,
		Comment:          comment,
		LifetimeSecs:     uint32((*twofa.Duration).Seconds()),
		ConfirmBeforeUse: confirmBeforeUse,
	}

	//comment should be based on key type?
	err = sshagent.WithAddedKeyUpsertCertIntoAgent(keyToAdd, logger)
	if err == nil {
		return nil
	}
	logger.Debugf(1, "Non fatal, failed to insert into agent with expiration")
	// NOTE: Current Windows ssh (OpenSSH_for_Windows_7.7p1, LibreSSL 2.6.5)
	// barfs on timeouts missing, so we rety without a timeout in case
	// we are on windows OR we have an agent running on windows thar is forwarded
	// to us.
	keyToAdd.LifetimeSecs = 0
	// confirmation is also broken on windows, but since it is an opt-in security
	// feature we never change the user preference
	err = sshagent.WithAddedKeyUpsertCertIntoAgent(keyToAdd, logger)
	if err == nil {
		return nil
	}
	logger.Debugf(1, "Non fatal, failed to insert into agent without expiration")
	encodedSigner, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(
		privateKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedSigner}),
		0600)
	if err != nil {
		return err
	}
	// now we need to write the certificate
	sshCertPath := privateKeyPath + ".pub"
	return ioutil.WriteFile(sshCertPath, certText, 0644)
}

func makeDirs(homeDir string) error {
	sshKeyPath := filepath.Join(homeDir, DefaultSSHKeysLocation, FilePrefix)
	sshConfigPath, _ := filepath.Split(sshKeyPath)
	if err := os.MkdirAll(sshConfigPath, 0700); err != nil {
		return err
	}
	tlsKeyPath := filepath.Join(homeDir, DefaultTLSKeysLocation, FilePrefix)
	tlsConfigPath, _ := filepath.Split(tlsKeyPath)
	if err := os.MkdirAll(tlsConfigPath, 0700); err != nil {
		return err
	}
	return nil
}

func setupCerts(
	userName string,
	homeDir string,
	configContents config.AppConfigFile,
	client *http.Client,
	logger log.DebugLogger) error {
	signers := makeSigners()
	//initialize the client connection
	targetURLs := strings.Split(configContents.Base.Gen_Cert_URLS, ",")
	err := backgroundConnectToAnyKeymasterServer(targetURLs, client, logger)
	if err != nil {
		return err
	}
	if err := makeDirs(homeDir); err != nil {
		return err
	}
	sshKeyPath := filepath.Join(homeDir, DefaultSSHKeysLocation, FilePrefix)
	tlsKeyPath := filepath.Join(homeDir, DefaultTLSKeysLocation, FilePrefix)
	var baseUrl string
	_webauthBrowser := configContents.Base.WebauthBrowser
	if *webauthBrowser != "" {
		_webauthBrowser = *webauthBrowser
	}
	if _webauthBrowser != "" {
		// Authenticate using web browser.
		baseUrl, err = webauth.Authenticate(userName, _webauthBrowser,
			filepath.Join(homeDir, keymasterSubdir, FilePrefix+".webtoken"),
			targetURLs, client, userAgentString, logger)
		if err != nil {
			return err
		}
	} else {
		// Authenticate using password and possible 2nd factor.
		password, err := util.GetUserCreds(userName)
		if err != nil {
			return err
		}
		baseUrl, err = twofa.AuthenticateToTargetUrls(userName, password,
			targetURLs, false, client,
			userAgentString, logger)
		if err != nil {
			return err

		}
	}
	if err := signers.Wait(); err != nil {
		return err
	}
	x509Cert, err := twofa.DoCertRequest(signers.X509Rsa, client, userName,
		baseUrl, "x509", configContents.Base.AddGroups, userAgentString, logger)
	if err != nil {
		return err
	}
	kubernetesCert, err := twofa.DoCertRequest(signers.X509Rsa, client,
		userName, baseUrl, "x509-kubernetes", configContents.Base.AddGroups,
		userAgentString, logger)
	if err != nil {
		logger.Debugf(0, "kubernetes cert not available")
	}
	sshRsaCert, err := twofa.DoCertRequest(signers.SshRsa, client, userName,
		baseUrl, "ssh", configContents.Base.AddGroups, userAgentString, logger)
	if err != nil {
		return err
	}
	sshEd25519Cert, err := twofa.DoCertRequest(signers.SshEd25519, client,
		userName, baseUrl, "ssh", configContents.Base.AddGroups,
		userAgentString, logger)
	if err != nil {
		logger.Debugf(1, "Ed25519 cert not available")
		sshEd25519Cert = nil
	}
	logger.Debugf(0, "certificates successfully generated")

	confirmKeyUse := configContents.Base.AgentConfirmUse
	// Time to write certs and keys
	// old agents do not understand sha2 certs, so we inject Ed25519 first
	// if present
	if sshEd25519Cert != nil {
		err = insertSSHCertIntoAgentORWriteToFilesystem(sshEd25519Cert,
			signers.SshEd25519,
			FilePrefix+"-ed25519",
			userName,
			sshKeyPath+"-ed25519",
			confirmKeyUse,
			logger)
		if err != nil {
			return err
		}
	}
	err = insertSSHCertIntoAgentORWriteToFilesystem(sshRsaCert,
		signers.SshRsa,
		FilePrefix+"-rsa",
		userName,
		sshKeyPath+"-rsa",
		confirmKeyUse,
		logger)
	if err != nil {
		return err
	}
	// Now x509
	encodedx509Signer, err := x509.MarshalPKCS8PrivateKey(signers.X509Rsa)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(
		tlsKeyPath+".key",
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedx509Signer}),
		0600)
	if err != nil {
		return err
	}
	x509CertPath := tlsKeyPath + ".cert"
	err = ioutil.WriteFile(x509CertPath, x509Cert, 0644)
	if err != nil {
		err := errors.New("Could not write ssh cert")
		logger.Fatal(err)
	}
	if kubernetesCert != nil {
		kubernetesCertPath := tlsKeyPath + "-kubernetes.cert"
		err = ioutil.WriteFile(kubernetesCertPath, kubernetesCert, 0644)
		if err != nil {
			err := errors.New("Could not write ssh cert")
			logger.Fatal(err)
		}
	}

	return nil

}

func computeUserAgent() {
	uaVersion := Version
	if Version == defaultVersionNumber {
		uaVersion = "0.0"
	}

	userAgentString = fmt.Sprintf("%s/%s (%s %s)", userAgentAppName, uaVersion, runtime.GOOS, runtime.GOARCH)
}

func getHttpClient(rootCAs *x509.CertPool, logger log.DebugLogger) (*http.Client, error) {
	var dialer libnet.Dialer
	rawDialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	if *roundRobinDialer {
		if rrDialer, err := rrdialer.New(rawDialer, "", logger); err != nil {
			logger.Fatalln(err)
		} else {
			defer rrDialer.WaitForBackgroundResults(time.Second)
			dialer = rrDialer
		}
	} else {
		dialer = rawDialer
	}
	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}
	return util.GetHttpClient(tlsConfig, dialer)
}

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [flags...] [aws-role-cert]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Version: %s\n", Version)
	flag.PrintDefaults()
}

func main() {
	flag.Usage = Usage
	flag.Parse()
	logger := cmdlogger.New()
	rootCAs, err := maybeGetRootCas(*rootCAFilename, logger)
	if err != nil {
		logger.Fatal(err)
	}
	client, err := getHttpClient(rootCAs, logger)
	if err != nil {
		logger.Fatal(err)
	}
	if *checkDevices {
		err = u2f.CheckU2FDevices(logger)
		if err != nil {
			logger.Fatal(err)
		}
		return
	}
	computeUserAgent()
	userName, homeDir, err := util.GetUserNameAndHomeDir()
	if err != nil {
		logger.Fatal(err)
	}
	config := loadConfigFile(client, logger)
	logger.Debugf(3, "loaded Config=%+v", config)
	// Adjust user name
	if len(config.Base.Username) > 0 {
		userName = config.Base.Username
	}
	// command line always wins over pref or config
	if *cliUsername != "" {
		userName = *cliUsername
	}
	if len(config.Base.FilePrefix) > 0 {
		FilePrefix = config.Base.FilePrefix
	}
	if *cliFilePrefix != "" {
		FilePrefix = *cliFilePrefix
	}
	if flag.Arg(0) == "aws-role-cert" {
		err = generateAwsRoleCert(homeDir, config, client, logger)
	} else {
		err = setupCerts(userName, homeDir, config, client, logger)
	}
	if err != nil {
		logger.Fatal(err)
	}
	logger.Printf("Success")
}
