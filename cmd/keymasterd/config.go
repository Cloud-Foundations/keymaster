package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/auth/userinfo/gitdb"
	acmecfg "github.com/Cloud-Foundations/golib/pkg/crypto/certmanager/config"
	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/keymasterd/admincache"
	"github.com/Cloud-Foundations/keymaster/lib/authenticators/okta"
	"github.com/Cloud-Foundations/keymaster/lib/pwauth/command"
	"github.com/Cloud-Foundations/keymaster/lib/pwauth/ldap"
	"github.com/Cloud-Foundations/keymaster/lib/vip"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

type autoUnseal struct {
	AwsSecretId  string `yaml:"aws_secret_id"`
	AwsSecretKey string `yaml:"aws_secret_key"`
}

type baseConfig struct {
	HttpAddress                  string `yaml:"http_address"`
	AdminAddress                 string `yaml:"admin_address"`
	HttpRedirectPort             uint16 `yaml:"http_redirect_port"`
	TLSCertFilename              string `yaml:"tls_cert_filename"`
	TLSKeyFilename               string `yaml:"tls_key_filename"`
	ACME                         acmecfg.AcmeConfig
	SSHCAFilename                string     `yaml:"ssh_ca_filename"`
	AutoUnseal                   autoUnseal `yaml:"auto_unseal"`
	HtpasswdFilename             string     `yaml:"htpasswd_filename"`
	ExternalAuthCmd              string     `yaml:"external_auth_command"`
	ClientCAFilename             string     `yaml:"client_ca_filename"`
	KeymasterPublicKeysFilename  string     `yaml:"keymaster_public_keys_filename"`
	HostIdentity                 string     `yaml:"host_identity"`
	KerberosRealm                string     `yaml:"kerberos_realm"`
	DataDirectory                string     `yaml:"data_directory"`
	SharedDataDirectory          string     `yaml:"shared_data_directory"`
	HideStandardLogin            bool       `yaml:"hide_standard_login"`
	AllowedAuthBackendsForCerts  []string   `yaml:"allowed_auth_backends_for_certs"`
	AllowedAuthBackendsForWebUI  []string   `yaml:"allowed_auth_backends_for_webui"`
	AdminUsers                   []string   `yaml:"admin_users"`
	AdminGroups                  []string   `yaml:"admin_groups"`
	PublicLogs                   bool       `yaml:"public_logs"`
	SecsBetweenDependencyChecks  int        `yaml:"secs_between_dependency_checks"`
	AutomationUserGroups         []string   `yaml:"automation_user_groups"`
	AutomationUsers              []string   `yaml:"automation_users"`
	DisableUsernameNormalization bool       `yaml:"disable_username_normalization"`
	EnableLocalTOTP              bool       `yaml:"enable_local_totp"`
}

type GitDatabaseConfig struct {
	gitdb.Config `yaml:",inline"`
	GroupPrepend string `yaml:"group_prepend"`
}

type LdapConfig struct {
	BindPattern          string `yaml:"bind_pattern"`
	LDAPTargetURLs       string `yaml:"ldap_target_urls"`
	DisablePasswordCache bool   `yaml:"disable_password_cache"`
}

type OktaConfig struct {
	Domain               string `yaml:"domain"`
	Enable2FA            bool   `yaml:"enable_2fa"`
	UsernameFilterRegexp string `yaml:"username_filter_regexp"`
}

type UserInfoLDAPSource struct {
	BindUsername       string   `yaml:"bind_username"`
	BindPassword       string   `yaml:"bind_password"`
	GroupPrepend       string   `yaml:"group_prepend"`
	LDAPTargetURLs     string   `yaml:"ldap_target_urls"`
	UserSearchBaseDNs  []string `yaml:"user_search_base_dns"`
	UserSearchFilter   string   `yaml:"user_search_filter"`
	GroupSearchBaseDNs []string `yaml:"group_search_base_dns"`
	GroupSearchFilter  string   `yaml:"group_search_filter"`
}

type UserInfoSouces struct {
	GitDB GitDatabaseConfig
	Ldap  UserInfoLDAPSource
}

type Oauth2Config struct {
	Config       *oauth2.Config
	Enabled      bool   `yaml:"enabled"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	TokenUrl     string `yaml:"token_url"`
	AuthUrl      string `yaml:"auth_url"`
	UserinfoUrl  string `yaml:"userinfo_url"`
	Scopes       string `yaml:"scopes"`
	//Todo add allowed orgs...
}

type OpenIDConnectClientConfig struct {
	ClientID               string   `yaml:"client_id"`
	ClientSecret           string   `yaml:"client_secret"`
	AllowedRedirectURLRE   []string `yaml:"allowed_redirect_url_re"`
	AllowedRedirectDomains []string `yaml:"allowed_redirect_domains"`
}

type OpenIDConnectIDPConfig struct {
	DefaultEmailDomain string                      `yaml:"default_email_domain"`
	Client             []OpenIDConnectClientConfig `yaml:"clients"`
}

type ProfileStorageConfig struct {
	AwsSecretId         string `yaml:"aws_secret_id"`
	StorageUrl          string `yaml:"storage_url"`
	TLSRootCertFilename string `yaml:"tls_root_cert_filename"`
}

type SymantecVIPConfig struct {
	Client            *vip.Client
	Enabled           bool   `yaml:"enabled"`
	CertFile          string `yaml:"cert_file"`
	KeyFile           string `yaml:"key_file"`
	RequireAppAproval bool   `yaml:"require_app_approval"`
}

type AppConfigFile struct {
	Base             baseConfig
	Ldap             LdapConfig
	Okta             OktaConfig
	UserInfo         UserInfoSouces `yaml:"userinfo_sources"`
	Oauth2           Oauth2Config
	OpenIDConnectIDP OpenIDConnectIDPConfig `yaml:"openid_connect_idp"`
	SymantecVIP      SymantecVIPConfig
	ProfileStorage   ProfileStorageConfig
}

const (
	defaultRSAKeySize                  = 3072
	defaultSecsBetweenDependencyChecks = 60
	defaultOktaUsernameFilterRegexp    = "@.*"
)

func (state *RuntimeState) loadTemplates() (err error) {
	//Load extra templates
	templatesPath := filepath.Join(state.Config.Base.SharedDataDirectory, "customization_data", "templates")
	if _, err = os.Stat(templatesPath); err != nil {
		return err
	}
	state.htmlTemplate = template.New("main")
	templateFiles := []string{"footer_extra.tmpl", "header_extra.tmpl", "login_extra.tmpl"}
	for _, templateFilename := range templateFiles {
		templatePath := filepath.Join(templatesPath, templateFilename)
		_, err = state.htmlTemplate.ParseFiles(templatePath)
		if err != nil {
			return err
		}
	}
	/// Load the oter built in templates
	extraTemplates := []string{footerTemplateText, loginFormText, secondFactorAuthFormText,
		profileHTML, usersHTML, headerTemplateText, newTOTPHTML}
	for _, templateString := range extraTemplates {
		_, err = state.htmlTemplate.Parse(templateString)
		if err != nil {
			return err
		}
	}
	return nil
}

func (state *RuntimeState) signerPublicKeyToKeymasterKeys() error {
	logger.Debugf(3, "number of pk known=%d", len(state.KeymasterPublicKeys))
	signerPKFingerprint, err := getKeyFingerprint(state.Signer.Public())
	if err != nil {
		return err
	}
	found := false
	for _, key := range state.KeymasterPublicKeys {
		fp, err := getKeyFingerprint(key)
		if err != nil {
			return err
		}
		if signerPKFingerprint == fp {
			found = true
		}
	}
	if !found {
		state.KeymasterPublicKeys = append(state.KeymasterPublicKeys, state.Signer.Public())
	}
	logger.Debugf(3, "number of pk known=%d", len(state.KeymasterPublicKeys))
	return nil
}

func warnInsecureConfiguration(state *RuntimeState) {
	warnInsercureClientConfig := false
	var insecureClientID []string
	for _, client := range state.Config.OpenIDConnectIDP.Client {
		if len(client.AllowedRedirectDomains) < 1 {
			warnInsercureClientConfig = true
			insecureClientID = append(insecureClientID, client.ClientID)
		}
	}
	if warnInsercureClientConfig {
		logger.Printf("At least some client openid configurations do NOT have domains attached. "+
			"This is dangerous. Affected clients: %v", insecureClientID)
	}
}

func loadVerifyConfigFile(configFilename string,
	logger log.DebugLogger) (*RuntimeState, error) {
	runtimeState := RuntimeState{
		isAdminCache: admincache.New(5 * time.Minute),
		logger:       logger,
	}
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return nil, err
	}
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %s", err)
	}
	err = yaml.Unmarshal(source, &runtimeState.Config)
	if err != nil {
		return nil, fmt.Errorf("cannot parse config file: %s", err)
	}

	//share config
	//runtimeState.userProfile = make(map[string]userProfile)
	runtimeState.pendingOauth2 = make(map[string]pendingAuth2Request)
	runtimeState.SignerIsReady = make(chan bool, 1)
	runtimeState.localAuthData = make(map[string]localUserData)
	runtimeState.vipPushCookie = make(map[string]pushPollTransaction)
	runtimeState.totpLocalRateLimit = make(map[string]totpRateLimitInfo)

	//verify config
	if len(runtimeState.Config.Base.HostIdentity) > 0 {
		runtimeState.HostIdentity = runtimeState.Config.Base.HostIdentity
	} else {
		runtimeState.HostIdentity, err = getHostIdentity()
		if err != nil {
			return nil, err
		}
	}
	runtimeState.Config.Base.AutoUnseal.applyDefaults()
	if err := runtimeState.expandStorageUrl(); err != nil {
		logger.Println(err)
	}
	// TODO: This assumes httpAddress is just the port..
	u2fAppID = "https://" + runtimeState.HostIdentity
	if runtimeState.Config.Base.HttpAddress != ":443" {
		u2fAppID = u2fAppID + runtimeState.Config.Base.HttpAddress
	}
	u2fTrustedFacets = append(u2fTrustedFacets, u2fAppID)

	if len(runtimeState.Config.Base.KerberosRealm) > 0 {
		runtimeState.KerberosRealm = &runtimeState.Config.Base.KerberosRealm
	}
	if err := runtimeState.setupCertificateManager(); err != nil {
		return nil, err
	}
	sshCAFilename := runtimeState.Config.Base.SSHCAFilename
	runtimeState.SSHCARawFileContent, err = exitsAndCanRead(sshCAFilename, "ssh CA File")
	if err != nil {
		logger.Printf("Cannot load ssh CA File")
		return nil, err
	}

	if len(runtimeState.Config.Base.ClientCAFilename) > 0 {
		buffer, err := exitsAndCanRead(
			runtimeState.Config.Base.ClientCAFilename, "client CA file")
		if err != nil {
			logger.Printf("Cannot load client CA File")
			return nil, err
		}
		runtimeState.ClientCAPool = x509.NewCertPool()
		ok := runtimeState.ClientCAPool.AppendCertsFromPEM(buffer)
		if !ok {
			err = errors.New("Cannot append any certs from Client CA file")
			return nil, err
		}
		logger.Debugf(3, "client ca file loaded %d ", len(runtimeState.ClientCAPool.Subjects()))

	}
	if len(runtimeState.Config.Base.KeymasterPublicKeysFilename) > 0 {
		filename := runtimeState.Config.Base.KeymasterPublicKeysFilename
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			logger.Printf("keymaster_public_keys_filename defined but file does not exist")
			return nil, err
		}
		inFile, err := os.Open(filename)
		if err != nil {
			logger.Printf("keymaster_public_keys_filename cannot be opened")
			return nil, err
		}
		defer inFile.Close()
		scanner := bufio.NewScanner(inFile)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			logger.Debugf(2, "line='%s'", scanner.Text())
			userPubKey := scanner.Text()
			sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(userPubKey))
			if err != nil {
				return nil, err
			}
			//
			cryptokey, ok := sshPubKey.(ssh.CryptoPublicKey)
			if !ok {
				err := errors.New("cannot cast public key!")
				return nil, err
			}
			logger.Debugf(3, "adding")
			runtimeState.KeymasterPublicKeys = append(runtimeState.KeymasterPublicKeys, cryptokey.CryptoPublicKey())

		}
	}

	if strings.HasPrefix(string(runtimeState.SSHCARawFileContent[:]), "-----BEGIN RSA PRIVATE KEY-----") {
		signer, err := getSignerFromPEMBytes(runtimeState.SSHCARawFileContent)
		if err != nil {
			logger.Printf("Cannot parse Private Key file")
			return nil, err
		}
		runtimeState.caCertDer, err = generateCADer(&runtimeState, signer)
		if err != nil {
			logger.Printf("Cannot generate CA DER")
			return nil, err
		}
		// Assignment of signer MUST be the last operation after
		// all error checks
		runtimeState.Signer = signer
		runtimeState.signerPublicKeyToKeymasterKeys()
		runtimeState.SignerIsReady <- true

	} else {
		//check that the loaded data seems like an openpgp armored file
		fileAsString := string(runtimeState.SSHCARawFileContent[:])
		if !strings.HasPrefix(fileAsString, "-----BEGIN PGP MESSAGE-----") {
			return nil, errors.New("CA private key file does NOT look like PGP")
		}
		logger.Println("Starting up in sealed state")
		if runtimeState.ClientCAPool == nil {
			logger.Println("No client CA: manual unsealing not possible")
		}
		runtimeState.beginAutoUnseal()
	}
	//create the oath2 config
	if runtimeState.Config.Oauth2.Enabled == true {
		logger.Printf("oath2 is enabled")
		runtimeState.Config.Oauth2.Config = &oauth2.Config{
			ClientID:     runtimeState.Config.Oauth2.ClientID,
			ClientSecret: runtimeState.Config.Oauth2.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  runtimeState.Config.Oauth2.AuthUrl,
				TokenURL: runtimeState.Config.Oauth2.TokenUrl},
			RedirectURL: "https://" + runtimeState.HostIdentity + runtimeState.Config.Base.HttpAddress + redirectPath,
			Scopes:      strings.Split(runtimeState.Config.Oauth2.Scopes, " ")}
	}
	if runtimeState.Config.SymantecVIP.Enabled == true {
		logger.Printf("symantec VIP is enabled")
		certPem, err := exitsAndCanRead(runtimeState.Config.SymantecVIP.CertFile, "VIP certificate file")
		if err != nil {
			return nil, err
		}

		keyPem, err := exitsAndCanRead(runtimeState.Config.SymantecVIP.KeyFile, "VIP key file")
		if err != nil {
			return nil, err
		}

		client, err := vip.NewClient(certPem, keyPem)
		if err != nil {
			return nil, err
		}
		client.VipPushMessageText = "Keymaster Push Authentication Request"
		client.VipPushDisplayMessageText = "Keymaster 2FA request from:"
		client.VipPushDisplayMessageProfile = u2fAppID //TODO change this for host identity
		client.RequireAppApproval = runtimeState.Config.SymantecVIP.RequireAppAproval
		runtimeState.Config.SymantecVIP.Client = &client
	}

	//
	if runtimeState.Config.Base.HideStandardLogin && !runtimeState.Config.Oauth2.Enabled {
		err := errors.New("invalid configuration... cannot hide std login without enabling oath2")
		return nil, err
	}

	//Load extra templates
	err = runtimeState.loadTemplates()
	if err != nil {
		return nil, err
	}

	// TODO(rgooch): We should probably support a priority list of
	// authentication backends which are tried in turn. The current scheme is
	// hacky and is limited to only one authentication backend.
	// ExtAuthCommand
	if len(runtimeState.Config.Base.ExternalAuthCmd) > 0 {
		runtimeState.passwordChecker, err = command.New(runtimeState.Config.Base.ExternalAuthCmd, nil, logger)
		if err != nil {
			return nil, err
		}
	}
	if oktaConfig := runtimeState.Config.Okta; oktaConfig.Domain != "" {
		runtimeState.passwordChecker, err = okta.NewPublic(oktaConfig.Domain,
			logger)
		if err != nil {
			return nil, err
		}
		logger.Debugf(1, "passwordChecker= %+v", runtimeState.passwordChecker)
		usernameFilterRegexp := oktaConfig.UsernameFilterRegexp
		if usernameFilterRegexp == "" {
			usernameFilterRegexp = defaultOktaUsernameFilterRegexp
		}
		runtimeState.oktaUsernameFilterRE, err = regexp.Compile(
			usernameFilterRegexp)
		if err != nil {
			return nil, err
		}
	}
	if len(runtimeState.Config.Ldap.LDAPTargetURLs) > 0 {
		const timeoutSecs = 3
		pwdCache := &runtimeState
		if runtimeState.Config.Ldap.DisablePasswordCache {
			pwdCache = nil
		}
		runtimeState.passwordChecker, err = ldap.New(
			strings.Split(runtimeState.Config.Ldap.LDAPTargetURLs, ","),
			[]string{runtimeState.Config.Ldap.BindPattern},
			timeoutSecs, nil, pwdCache,
			logger)
		if err != nil {
			return nil, err
		}
		logger.Debugf(1, "passwordChecker= %+v", runtimeState.passwordChecker)
	}
	if runtimeState.Config.Base.SecsBetweenDependencyChecks < 1 {
		runtimeState.Config.Base.SecsBetweenDependencyChecks = defaultSecsBetweenDependencyChecks
	}

	logger.Debugf(1, "End of config initialization: %+v", &runtimeState)

	// UserInfo setup.
	if runtimeState.Config.UserInfo.GitDB.LocalRepositoryDirectory != "" {
		gitdbConfig := runtimeState.Config.UserInfo.GitDB
		runtimeState.gitDB, err = gitdb.NewWithConfig(gitdbConfig.Config,
			logger)
		if err != nil {
			return nil, err
		}
		logger.Println("loaded UserInfo GitDB")
	}

	// Warn on potential issues
	warnInsecureConfiguration(&runtimeState)

	// DB initialization
	err = initDB(&runtimeState)
	if err != nil {
		return nil, err
	}

	// and we start the cleanup
	go runtimeState.performStateCleanup(secsBetweenCleanup)

	//
	go runtimeState.doDependencyMonitoring(runtimeState.Config.Base.SecsBetweenDependencyChecks)

	return &runtimeState, nil
}

func (state *RuntimeState) setupCertificateManager() error {
	baseConfig := state.Config.Base
	if len(baseConfig.ACME.DomainNames) < 1 {
		baseConfig.ACME.DomainNames = []string{baseConfig.HostIdentity}
	}
	cm, err := acmecfg.New(baseConfig.TLSCertFilename,
		baseConfig.TLSKeyFilename, baseConfig.HttpRedirectPort,
		baseConfig.ACME, state.logger)
	if err != nil {
		return err
	}
	state.certManager = cm
	return nil
}

func generateArmoredEncryptedCAPrivateKey(passphrase []byte,
	filepath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	if err != nil {
		return err
	}
	sshPublicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	publicKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)
	err = ioutil.WriteFile(filepath+".pub", publicKeyBytes, 0644)
	if err != nil {
		return err
	}
	encryptionType := "PGP MESSAGE"
	armoredBuf := new(bytes.Buffer)
	armoredWriter, err := armor.Encode(armoredBuf, encryptionType, nil)
	if err != nil {
		return err
	}
	var plaintextWriter io.WriteCloser
	if len(passphrase) < 1 {
		plaintextWriter, err = os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY,
			0600)
	} else {
		plaintextWriter, err = openpgp.SymmetricallyEncrypt(armoredWriter,
			passphrase, nil, nil)
	}
	if err != nil {
		return err
	}
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(plaintextWriter, privateKeyPEM); err != nil {
		return err
	}
	if err := plaintextWriter.Close(); err != nil {
		return err
	}
	if len(passphrase) < 1 {
		return nil
	} else {
		armoredWriter.Close()
		return ioutil.WriteFile(filepath, armoredBuf.Bytes(), 0600)
	}
}

func getPassphrase() ([]byte, error) {
	///matching := false
	for {
		fmt.Printf("Please enter your passphrase:\n")
		passphrase1, err := gopass.GetPasswd()
		if err != nil {
			return nil, err
		}
		fmt.Printf("Please re-enter your passphrase:\n")
		passphrase2, err := gopass.GetPasswd()
		if err != nil {
			return nil, err
		}
		if bytes.Equal(passphrase1, passphrase2) {
			return passphrase1, nil
		}
		fmt.Printf("Passphrases dont match, lets try again ")

	}
}

func getUserString(reader *bufio.Reader, displayValue, defaultValue string) (string, error) {
	fmt.Printf("%s[%s]:", displayValue, defaultValue)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(text) > 1 {
		return text, nil
	}
	return defaultValue, nil
}

func generateRSAKeyAndSaveInFile(filename string, bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		bits = defaultRSAKeySize
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(file, privateKeyPEM); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func generateCertAndWriteToFile(filename string, template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		logger.Printf("Failed to create certificate: %s", err)
		return nil, err
	}
	certOut, err := os.Create(filename)
	if err != nil {
		logger.Printf("failed to open cert.pem for writing: %s", err)
		return nil, err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	logger.Print("written cert.pem\n")
	return derBytes, nil
}

func generateCerts(configDir string, config *baseConfig, rsaKeySize int,
	needAdminCA bool) error {
	//First generate a self signeed cert for itelf
	serverKeyFilename := configDir + "/server.key"
	serverKey, err := generateRSAKeyAndSaveInFile(serverKeyFilename, rsaKeySize)
	if err != nil {
		return err
	}
	// Now make the cert
	notBefore := time.Now()
	validFor := time.Duration(5 * 365 * 24 * time.Hour)
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Printf("failed to generate serial number: %s", err)
		return err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	template.DNSNames = append(template.DNSNames, "localhost")
	serverCertFilename := configDir + "/server.pem"
	_, err = generateCertAndWriteToFile(serverCertFilename, &template, &template,
		&serverKey.PublicKey, serverKey)
	if err != nil {
		logger.Printf("Failed to create certificate: %s", err)
		return err
	}
	caTemplate := template
	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Printf("failed to generate serial number: %s", err)
		return err
	}
	caTemplate.DNSNames = nil
	caTemplate.SerialNumber = serialNumber
	caTemplate.IsCA = true
	caTemplate.KeyUsage |= x509.KeyUsageCertSign
	caTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth}
	caTemplate.Subject = pkix.Name{Organization: []string{"Acme Co CA"}}
	if needAdminCA {
		err := config.createAdminCA(configDir, rsaKeySize, template, caTemplate)
		if err != nil {
			return err
		}
	}
	config.TLSKeyFilename = serverKeyFilename
	config.TLSCertFilename = serverCertFilename
	return nil
}

func (config *baseConfig) createAdminCA(configDir string,
	rsaKeySize int, template, caTemplate x509.Certificate) error {
	adminCAKeyFilename := configDir + "/adminCA.key"
	adminCAKey, err := generateRSAKeyAndSaveInFile(adminCAKeyFilename,
		rsaKeySize)
	if err != nil {
		return err
	}
	adminCACertFilename := configDir + "/adminCA.pem"
	config.ClientCAFilename = adminCACertFilename
	caDer, err := generateCertAndWriteToFile(adminCACertFilename,
		&caTemplate, &caTemplate, &adminCAKey.PublicKey, adminCAKey)
	if err != nil {
		logger.Printf("Failed to create certificate: %s", err)
		return err
	}
	// Now the admin client
	caCert, err := x509.ParseCertificate(caDer)
	if err != nil {
		logger.Printf("Failed to parse certificate: %s", err)
		return err
	}
	clientKeyFilename := configDir + "/adminClient.key"
	clientKey, err := generateRSAKeyAndSaveInFile(clientKeyFilename,
		rsaKeySize)
	if err != nil {
		logger.Printf("Failed to generate file for key: %s", err)
		return err
	}
	//Fix template!
	clientTemplate := template
	//client.KeyUsage |= ExtKeyUsageClientAuth
	clientTemplate.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	clientCertFilename := configDir + "/adminClient.pem"
	_, err = generateCertAndWriteToFile(clientCertFilename, &clientTemplate,
		caCert, &clientKey.PublicKey, adminCAKey)
	if err != nil {
		logger.Printf("Failed to create certificate: %s", err)
		return err
	}
	return nil
}

func generateNewConfig(configFilename string) error {
	reader := bufio.NewReader(os.Stdin)
	const rsaKeySize = 3072
	passphrase, err := getPassphrase()
	if err != nil {
		logger.Printf("error getting passphrase")
		return err
	}
	return generateNewConfigInternal(reader, configFilename, rsaKeySize, passphrase)
}

// Generates a simple base config via an interview like process
func generateNewConfigInternal(reader *bufio.Reader, configFilename string,
	rsaKeySize int, passphrase []byte) error {
	var config AppConfigFile
	//Get base dir
	baseDir, err := getUserString(reader, "Default base Dir", "/tmp")
	if err != nil {
		return err
	}
	baseDir = strings.Trim(baseDir, "\r\n")
	//make dest tartget
	configDir := filepath.Join(baseDir, "/etc/keymaster")
	logger.Printf("configdir = '%s'", configDir)
	err = os.MkdirAll(configDir, os.ModeDir|0755)
	if err != nil {
		return err
	}
	config.Base.DataDirectory, err = getUserString(reader, "Data Directory",
		baseDir+"/var/lib/keymaster")
	if err != nil {
		return err
	}
	err = os.MkdirAll(config.Base.DataDirectory, os.ModeDir|0755)
	if err != nil {
		return err
	}
	// TODO: Add check that directory exists.
	defaultHttpAddress := ":443"
	config.Base.HttpAddress, err = getUserString(reader, "HttpAddress",
		defaultHttpAddress)
	if err != nil {
		return err
	}
	// Todo check if valid
	defaultAdminAddress := ":6920"
	config.Base.AdminAddress, err = getUserString(reader, "AdminAddress",
		defaultAdminAddress)
	if err != nil {
		return err
	}
	config.Base.SSHCAFilename = filepath.Join(configDir, "masterKey.asc")
	err = generateArmoredEncryptedCAPrivateKey(passphrase,
		config.Base.SSHCAFilename)
	if err != nil {
		return err
	}
	needAdminCA := false
	if len(passphrase) > 0 {
		needAdminCA = true
	}
	err = generateCerts(configDir, &config.Base, rsaKeySize, needAdminCA)
	if err != nil {
		return err
	}
	//make sample apache config file
	// This DB has user 'username' with password 'password'
	const userdbContent = `username:$2y$05$D4qQmZbWYqfgtGtez2EGdOkcNne40EdEznOqMvZegQypT8Jdz42Jy`
	httpPassFilename := filepath.Join(configDir, "passfile.htpass")
	err = ioutil.WriteFile(httpPassFilename, []byte(userdbContent), 0644)
	if err != nil {
		return err
	}
	config.Base.HtpasswdFilename = httpPassFilename
	logger.Debugf(1, "%+v", config)
	configText, err := yaml.Marshal(&config)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(configFilename, configText, 0640)
	if err != nil {
		return err
	}
	fmt.Printf("--- config dump:\n%s\n\n", string(configText))
	return nil
}
