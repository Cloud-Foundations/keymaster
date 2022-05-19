package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/auth/userinfo/gitdb"
	"github.com/Cloud-Foundations/golib/pkg/communications/configuredemail"
	acmecfg "github.com/Cloud-Foundations/golib/pkg/crypto/certmanager/config"
	dnslbcfg "github.com/Cloud-Foundations/golib/pkg/loadbalancing/dnslb/config"
	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/golib/pkg/watchdog"
	"github.com/Cloud-Foundations/keymaster/keymasterd/admincache"
	"github.com/Cloud-Foundations/keymaster/lib/authenticators/okta"
	"github.com/Cloud-Foundations/keymaster/lib/pwauth/command"
	"github.com/Cloud-Foundations/keymaster/lib/pwauth/htpassword"
	"github.com/Cloud-Foundations/keymaster/lib/pwauth/ldap"
	"github.com/Cloud-Foundations/keymaster/lib/vip"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v2"
)

type autoUnseal struct {
	AwsSecretId  string `yaml:"aws_secret_id"`
	AwsSecretKey string `yaml:"aws_secret_key"`
}

type baseConfig struct {
	HttpAddress                     string `yaml:"http_address"`
	AdminAddress                    string `yaml:"admin_address"`
	HttpRedirectPort                uint16 `yaml:"http_redirect_port"`
	TLSCertFilename                 string `yaml:"tls_cert_filename"`
	TLSKeyFilename                  string `yaml:"tls_key_filename"`
	ACME                            acmecfg.AcmeConfig
	SSHCAFilename                   string        `yaml:"ssh_ca_filename"`
	Ed25519CAFilename               string        `yaml:"ed25519_ca_keyfilename"`
	AutoUnseal                      autoUnseal    `yaml:"auto_unseal"`
	HtpasswdFilename                string        `yaml:"htpasswd_filename"`
	ExternalAuthCmd                 string        `yaml:"external_auth_command"`
	ClientCAFilename                string        `yaml:"client_ca_filename"`
	KeymasterPublicKeysFilename     string        `yaml:"keymaster_public_keys_filename"`
	HostIdentity                    string        `yaml:"host_identity"`
	KerberosRealm                   string        `yaml:"kerberos_realm"`
	DataDirectory                   string        `yaml:"data_directory"`
	SharedDataDirectory             string        `yaml:"shared_data_directory"`
	AllowedAuthBackendsForCerts     []string      `yaml:"allowed_auth_backends_for_certs"`
	AllowedAuthBackendsForWebUI     []string      `yaml:"allowed_auth_backends_for_webui"`
	AllowSelfServiceBootstrapOTP    bool          `yaml:"allow_self_service_bootstrap_otp"`
	AdminUsers                      []string      `yaml:"admin_users"`
	AdminGroups                     []string      `yaml:"admin_groups"`
	PublicLogs                      bool          `yaml:"public_logs"`
	SecsBetweenDependencyChecks     int           `yaml:"secs_between_dependency_checks"`
	AutomationUserGroups            []string      `yaml:"automation_user_groups"`
	AutomationUsers                 []string      `yaml:"automation_users"`
	DisableUsernameNormalization    bool          `yaml:"disable_username_normalization"`
	EnableLocalTOTP                 bool          `yaml:"enable_local_totp"`
	EnableBootstrapOTP              bool          `yaml:"enable_bootstrapotp"`
	WebauthTokenForCliLifetime      time.Duration `yaml:"webauth_token_for_cli_lifetime"`
	PasswordAttemptGlobalBurstLimit uint          `yaml:"password_attempt_global_burst_limit"`
	PasswordAttemptGlobalRateLimit  rate.Limit    `yaml:"password_attempt_global_rate_limit"`
}

type awsCertsConfig struct {
	AllowedAccounts      []string `yaml:"allowed_accounts"`
	ListAccountsRole     string   `yaml:"list_accounts_role"`
	allowedAccounts      map[string]struct{}
	organisationAccounts map[string]struct{}
}

type emailConfig struct {
	configuredemail.EmailConfig `yaml:",inline"`
	Domain                      string
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
	UsernameSuffix       string `yaml:"username_suffix"`
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
	Config        *oauth2.Config
	Enabled       bool   `yaml:"enabled"`
	ForceRedirect bool   `yaml:"force_redirect"`
	ClientID      string `yaml:"client_id"`
	ClientSecret  string `yaml:"client_secret"`
	TokenUrl      string `yaml:"token_url"`
	AuthUrl       string `yaml:"auth_url"`
	UserinfoUrl   string `yaml:"userinfo_url"`
	Scopes        string `yaml:"scopes"`
	//Todo add allowed orgs...
}

type OpenIDConnectClientConfig struct {
	ClientID                   string   `yaml:"client_id"`
	ClientSecret               string   `yaml:"client_secret"`
	AllowClientChosenAudiences bool     `yaml:"allow_client_chose_audiences"`
	AllowedRedirectURLRE       []string `yaml:"allowed_redirect_url_re"`
	AllowedRedirectDomains     []string `yaml:"allowed_redirect_domains"`
}

type OpenIDConnectIDPConfig struct {
	DefaultEmailDomain string                      `yaml:"default_email_domain"`
	Client             []OpenIDConnectClientConfig `yaml:"clients"`
}

type ProfileStorageConfig struct {
	AwsSecretId         string        `yaml:"aws_secret_id"`
	ConnectionLifetime  time.Duration `yaml:"connection_lifetime"`
	StorageUrl          string        `yaml:"storage_url"`
	SyncDelay           time.Duration `yaml:"sync_delay"`
	SyncInterval        time.Duration `yaml:"sync_interval"`
	TLSRootCertFilename string        `yaml:"tls_root_cert_filename"`
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
	AwsCerts         awsCertsConfig  `yaml:"aws_certs"`
	DnsLoadBalancer  dnslbcfg.Config `yaml:"dns_load_balancer"`
	Watchdog         watchdog.Config `yaml:"watchdog"`
	Email            emailConfig
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
	templatesPath := filepath.Join(state.Config.Base.SharedDataDirectory,
		"customization_data", "templates")
	if _, err = os.Stat(templatesPath); err != nil {
		return err
	}
	// Load HTML template files.
	state.htmlTemplate = htmltemplate.New("main")
	htmlTemplateFiles := []string{"footer_extra.tmpl", "header_extra.tmpl",
		"login_extra.tmpl"}
	for _, templateFilename := range htmlTemplateFiles {
		templatePath := filepath.Join(templatesPath, templateFilename)
		if _, err = state.htmlTemplate.ParseFiles(templatePath); err != nil {
			return err
		}
	}
	// Load the built-in HTML templates.
	htmlTemplates := []string{footerTemplateText, loginFormText,
		secondFactorAuthFormText, profileHTML, usersHTML, headerTemplateText,
		newTOTPHTML, newBootstrapOTPPHTML, showAuthTokenHTML,
	}
	for _, templateString := range htmlTemplates {
		_, err = state.htmlTemplate.Parse(templateString)
		if err != nil {
			return err
		}
	}
	state.textTemplates = texttemplate.New("text")
	// Load the built-in text templates.
	textTemplates := []string{emailAdminTemplateData, emailUserTemplateData}
	for _, templateString := range textTemplates {
		_, err = state.textTemplates.Parse(templateString)
		if err != nil {
			return err
		}
	}
	// Load text template files, which may override the built-in templates.
	textTemplateFiles := []string{"bootstrapOtpEmail.tmpl"}
	for _, templateFilename := range textTemplateFiles {
		templatePath := filepath.Join(templatesPath, templateFilename)
		if _, err = state.textTemplates.ParseFiles(templatePath); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func (state *RuntimeState) signerPublicKeyToKeymasterKeys() error {
	state.logger.Debugf(3, "number of pk known=%d",
		len(state.KeymasterPublicKeys))
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
		state.KeymasterPublicKeys = append(state.KeymasterPublicKeys,
			state.Signer.Public())
	}
	state.logger.Debugf(3, "number of pk known=%d",
		len(state.KeymasterPublicKeys))
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

func (state *RuntimeState) loadSignersFromPemData(signerPem, ed25519Pem []byte) error {
	if ed25519Pem != nil && len(ed25519Pem) > 0 {
		edSigner, err := getSignerFromPEMBytes(ed25519Pem)
		if err != nil {
			return err
		}
		switch v := edSigner.(type) {
		case ed25519.PrivateKey, *ed25519.PrivateKey:
			state.logger.Debugf(2, "Got an Ed25519 Private key")
		default:
			return fmt.Errorf("Ed2559 configred file is not really an Ed25519 key. Type is %T!\n", v)
		}
		state.Ed25519Signer = edSigner
	}
	signer, err := getSignerFromPEMBytes(signerPem)
	if err != nil {
		state.logger.Printf("Cannot parse Private Key file")
		return err
	}
	switch v := signer.(type) {
	case *rsa.PrivateKey:
		state.logger.Debugf(1, "Signer is RSA")
	case *ecdsa.PrivateKey:
		state.logger.Printf("Warning ECDSA keys are supported experimentally")
	default:
		return fmt.Errorf("Signer file is a valid Signer key. Type is %T!\n", v)
	}
	state.caCertDer, err = generateCADer(state, signer)
	if err != nil {
		state.logger.Printf("Cannot generate CA DER")
		return err
	}
	// Assignment of signer MUST be the last operation after
	// all error checks
	state.Signer = signer
	return nil
}

// Loads the verifies consistency of signers and loads them if plaintext
// or starts the autounselaing if encrypted
func (state *RuntimeState) tryLoadAndVerifySigners() error {
	state.logger.Debugf(2, "Top of tryLoadAndVerifySigners")
	signerBlock, _ := pem.Decode(state.SSHCARawFileContent)
	if signerBlock == nil {
		// it is not PEM.. probably armor.. ie encrypted?
		decbuf := bytes.NewBuffer(state.SSHCARawFileContent)
		armorSignerBlock, err := armor.Decode(decbuf)
		if err != nil {
			return fmt.Errorf("signer content is not pem encoded or armor encoded")
		}
		if len(state.Ed25519CAFileContent) > 0 {
			ed255buf := bytes.NewBuffer(state.Ed25519CAFileContent)
			ed255ArmorBlock, err := armor.Decode(ed255buf)
			if err != nil {
				return fmt.Errorf("Signer is armored but Ed25519 is not, will not start")
			}
			if ed255ArmorBlock.Type != armorSignerBlock.Type {
				return fmt.Errorf("Ed25519 and Signer blocks do not match will not start")
			}
		}
		state.logger.Debugf(3, "tryLoadAndVerifySigners: PEM is PGP")
		logger.Println("Starting up in sealed state")
		if state.ClientCAPool == nil {
			state.logger.Println("No client CA: manual unsealing not possible")
		}
		state.beginAutoUnseal()
		return nil
	}
	err := state.loadSignersFromPemData(state.SSHCARawFileContent, state.Ed25519CAFileContent)
	if err != nil {
		return err
	}
	state.signerPublicKeyToKeymasterKeys()
	state.SignerIsReady <- true
	return nil
}

func loadVerifyConfigFile(configFilename string,
	logger log.DebugLogger) (*RuntimeState, error) {
	runtimeState := RuntimeState{
		isAdminCache: admincache.New(5 * time.Minute),
		logger:       logger,
	}
	runtimeState.initEmailDefaults()
	runtimeState.Config.Watchdog.SetDefaults()
	runtimeState.Config.Base.PasswordAttemptGlobalBurstLimit = 100
	runtimeState.Config.Base.PasswordAttemptGlobalRateLimit = 10
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
	if runtimeState.Config.Base.PasswordAttemptGlobalBurstLimit < 10 {
		runtimeState.Config.Base.PasswordAttemptGlobalBurstLimit = 10
	}
	if runtimeState.Config.Base.PasswordAttemptGlobalRateLimit < 1 {
		runtimeState.Config.Base.PasswordAttemptGlobalRateLimit = 1
	}
	runtimeState.passwordAttemptGlobalLimiter = rate.NewLimiter(
		runtimeState.Config.Base.PasswordAttemptGlobalRateLimit,
		int(runtimeState.Config.Base.PasswordAttemptGlobalBurstLimit))

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
	if len(runtimeState.Config.Base.Ed25519CAFilename) > 0 {
		runtimeState.Ed25519CAFileContent, err = exitsAndCanRead(runtimeState.Config.Base.Ed25519CAFilename, "ssh CA File")
		if err != nil {
			logger.Printf("Cannot load Ed25519 CA File")
			return nil, err
		}
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
	err = runtimeState.tryLoadAndVerifySigners()
	if err != nil {
		return nil, err
	}
	if err := runtimeState.setupEmail(); err != nil {
		return nil, err
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

	//Load extra templates
	err = runtimeState.loadTemplates()
	if err != nil {
		return nil, err
	}
	if err := runtimeState.setupHA(); err != nil {
		return nil, err
	}
	// TODO(rgooch): We should probably support a priority list of
	// authentication backends which are tried in turn. The current scheme is
	// hacky and is limited to only one authentication backend.
	if runtimeState.Config.Base.HtpasswdFilename != "" {
		runtimeState.passwordChecker, err = htpassword.New(
			runtimeState.Config.Base.HtpasswdFilename, logger)
		if err != nil {
			return nil, err
		}
	}
	// ExtAuthCommand
	if len(runtimeState.Config.Base.ExternalAuthCmd) > 0 {
		runtimeState.passwordChecker, err = command.New(
			runtimeState.Config.Base.ExternalAuthCmd, nil, logger)
		if err != nil {
			return nil, err
		}
	}
	if oktaConfig := runtimeState.Config.Okta; oktaConfig.Domain != "" {
		runtimeState.passwordChecker, err = okta.NewPublic(oktaConfig.Domain,
			oktaConfig.UsernameSuffix, logger)
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
	// If not using an OAuth2 IDP for primary authentication, must have an
	// alternative enabled.
	if runtimeState.passwordChecker == nil &&
		!runtimeState.Config.Oauth2.Enabled {
		return nil, errors.New(
			"invalid configuration: no primary authentication method")
	}

	if runtimeState.Config.Base.SecsBetweenDependencyChecks < 1 {
		runtimeState.Config.Base.SecsBetweenDependencyChecks = defaultSecsBetweenDependencyChecks
	}
	if err := runtimeState.configureAwsRoles(); err != nil {
		return nil, err
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

	if runtimeState.Config.Base.WebauthTokenForCliLifetime >
		maxWebauthForCliTokenLifetime {
		runtimeState.Config.Base.WebauthTokenForCliLifetime =
			maxWebauthForCliTokenLifetime
	}

	// Warn on potential issues
	warnInsecureConfiguration(&runtimeState)

	// DB initialization
	if err := initDB(&runtimeState); err != nil {
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

func (state *RuntimeState) setupHA() error {
	_, portString, err := net.SplitHostPort(state.Config.Base.AdminAddress)
	if err != nil {
		return err
	}
	adminPort, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return err
	}
	if hasDnsLB, err := state.Config.DnsLoadBalancer.Check(); err != nil {
		return err
	} else if hasDnsLB {
		state.Config.DnsLoadBalancer.DoTLS = true
		if state.Config.DnsLoadBalancer.TcpPort < 1 {
			state.Config.DnsLoadBalancer.TcpPort = uint16(adminPort)
			if state.Config.DnsLoadBalancer.FQDN == "" {
				state.Config.DnsLoadBalancer.FQDN =
					state.Config.Base.HostIdentity
			}
		}
		_, err := dnslbcfg.New(state.Config.DnsLoadBalancer, logger)
		if err != nil {
			return err
		}
	}
	state.Config.Watchdog.DoTLS = true
	if state.Config.Watchdog.CheckInterval > 0 &&
		state.Config.Watchdog.TcpPort < 1 {
		state.Config.Watchdog.TcpPort = uint16(adminPort)
	}
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
			CommonName:   config.HostIdentity,
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
	defaultHostIdentity := "keymaster.DOMAIN"
	hostIdentity, err := getUserString(reader, "HostIdentity",
		defaultHostIdentity)
	if err != nil {
		return err
	}
	config.Base.HostIdentity = strings.TrimSpace(hostIdentity)
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
