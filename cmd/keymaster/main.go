package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/log/cmdlogger"
	"github.com/Cloud-Foundations/Dominator/lib/net/rrdialer"
	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/client/config"
	libnet "github.com/Cloud-Foundations/keymaster/lib/client/net"
	"github.com/Cloud-Foundations/keymaster/lib/client/sshagent"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa/u2f"
	"github.com/Cloud-Foundations/keymaster/lib/client/util"
)

const DefaultSSHKeysLocation = "/.ssh/"
const DefaultTLSKeysLocation = "/.ssl/"
const DefaultTMPKeysLocation = "/.keymaster/"

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
	configFilename   = flag.String("config", filepath.Join(getUserHomeDir(), ".keymaster", "client_config.yml"), "The filename of the configuration")
	rootCAFilename   = flag.String("rootCAFilename", "", "(optional) name for using non OS root CA to verify TLS connections")
	configHost       = flag.String("configHost", "", "Get a bootstrap config from this host")
	cliUsername      = flag.String("username", "", "username for keymaster")
	checkDevices     = flag.Bool("checkDevices", false, "CheckU2F devices in your system")
	cliFilePrefix    = flag.String("fileprefix", "", "Prefix for the output files")
	roundRobinDialer = flag.Bool("roundRobinDialer", false,
		"If true, use the smart round-robin dialer")

	FilePrefix = "keymaster"
)

func getUserHomeDir() (homeDir string) {
	homeDir = os.Getenv("HOME")
	if homeDir != "" {
		return homeDir
	}
	usr, err := user.Current()
	if err != nil {
		return homeDir
	}
	// TODO: verify on Windows... see: http://stackoverflow.com/questions/7922270/obtain-users-home-directory
	homeDir = usr.HomeDir
	return
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

func getUserNameAndHomeDir(logger log.Logger) (userName, homeDir string, err error) {
	usr, err := user.Current()
	if err != nil {
		logger.Printf("cannot get current user info")
		return "", "", err
	}
	userName = usr.Username

	if runtime.GOOS == "windows" {
		splitName := strings.Split(userName, "\\")
		if len(splitName) == 2 {
			userName = strings.ToLower(splitName[1])
		}
	}

	homeDir, err = util.GetUserHomeDir(usr)
	if err != nil {
		return "", "", err
	}
	return
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

func setupCerts(
	userName string,
	homeDir string,
	configContents config.AppConfigFile,
	client *http.Client,
	logger log.DebugLogger) {
	//initialize the client connection
	targetURLs := strings.Split(configContents.Base.Gen_Cert_URLS, ",")
	err := backgroundConnectToAnyKeymasterServer(targetURLs, client, logger)
	if err != nil {
		logger.Fatal(err)
	}

	// create dirs
	sshKeyPath := filepath.Join(homeDir, DefaultSSHKeysLocation, FilePrefix)
	sshConfigPath, _ := filepath.Split(sshKeyPath)
	err = os.MkdirAll(sshConfigPath, 0700)
	if err != nil {
		logger.Fatal(err)
	}
	tlsKeyPath := filepath.Join(homeDir, DefaultTLSKeysLocation, FilePrefix)
	tlsConfigPath, _ := filepath.Split(tlsKeyPath)
	err = os.MkdirAll(tlsConfigPath, 0700)
	if err != nil {
		logger.Fatal(err)
	}

	tempPrivateKeyPath := filepath.Join(homeDir, DefaultTMPKeysLocation, "keymaster-temp")
	tempPrivateConfigPath, _ := filepath.Split(tempPrivateKeyPath)
	err = os.MkdirAll(tempPrivateConfigPath, 0700)
	if err != nil {
		logger.Fatal(err)
	}

	// get signer
	signer, tempPublicKeyPath, err := util.GenKeyPair(
		tempPrivateKeyPath, userName+"@keymaster", logger)
	if err != nil {
		logger.Fatal(err)
	}
	defer os.Remove(tempPrivateKeyPath)
	defer os.Remove(tempPublicKeyPath)
	defer os.Remove(tempPrivateKeyPath)
	// Get user creds
	password, err := util.GetUserCreds(userName)
	if err != nil {
		logger.Fatal(err)
	}

	// Get the certs
	sshCert, x509Cert, kubernetesCert, err := twofa.GetCertFromTargetUrls(
		signer,
		userName,
		password,
		strings.Split(configContents.Base.Gen_Cert_URLS, ","),
		false,
		configContents.Base.AddGroups,
		client,
		userAgentString,
		logger)
	if err != nil {
		logger.Fatal(err)
	}
	if sshCert == nil || x509Cert == nil {
		err := errors.New("Could not get cert from any url")
		logger.Fatal(err)
	}
	logger.Debugf(0, "Got Certs from server")

	//rename files to expected paths
	err = os.Rename(tempPrivateKeyPath, sshKeyPath)
	if err != nil {
		err := errors.New("Could not rename private Key")
		logger.Fatal(err)
	}

	err = os.Rename(tempPublicKeyPath, sshKeyPath+".pub")
	if err != nil {
		err := errors.New("Could not rename public Key")
		logger.Fatal(err)
	}
	// Now handle the key in the tls directory
	tlsPrivateKeyName := filepath.Join(homeDir, DefaultTLSKeysLocation, FilePrefix+".key")
	os.Remove(tlsPrivateKeyName)
	err = os.Symlink(sshKeyPath, tlsPrivateKeyName)
	if err != nil {
		// Try to copy instead (windows symlink does not work)
		from, err := os.Open(sshKeyPath)
		if err != nil {
			logger.Fatal(err)
		}
		defer from.Close()
		to, err := os.OpenFile(tlsPrivateKeyName, os.O_RDWR|os.O_CREATE, 0660)
		if err != nil {
			logger.Fatal(err)
		}
		defer to.Close()

		_, err = io.Copy(to, from)
		if err != nil {
			logger.Fatal(err)
		}
	}

	// now we write the cert file...
	sshCertPath := sshKeyPath + "-cert.pub"
	err = ioutil.WriteFile(sshCertPath, sshCert, 0644)
	if err != nil {
		err := errors.New("Could not write ssh cert")
		logger.Fatal(err)
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

	// TODO eventually we should reorder operations so that we write to the
	// private key only if we are unable to use the agent
	err = sshagent.UpsertCertIntoAgent(sshCert, signer, FilePrefix+"-"+userName, uint32((*twofa.Duration).Seconds()), logger)
	if err != nil {
		// NOTE: Current Windows ssh (OpenSSH_for_Windows_7.7p1, LibreSSL 2.6.5)
		// barfs on timeouts missing, so we rety without a timeout in case
		// we are on windows OR we have an agent running on windows thar is forwarded
		// to us.
		err = sshagent.UpsertCertIntoAgent(sshCert, signer,
			FilePrefix+"-"+userName, 0, logger)
		if err != nil {
			logger.Printf("could not insert into agent natively")
		}
	}

	logger.Printf("Success")
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
	fmt.Fprintf(
		os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
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
		u2f.CheckU2FDevices(logger)
		return
	}
	computeUserAgent()

	userName, homeDir, err := getUserNameAndHomeDir(logger)
	if err != nil {
		logger.Fatal(err)
	}
	config := loadConfigFile(client, logger)

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

	setupCerts(userName, homeDir, config, client, logger)
}
