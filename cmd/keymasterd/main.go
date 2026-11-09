package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"embed"
	"flag"
	"fmt"
	htmltemplate "html/template"
	"io/fs"
	stdlog "log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	texttemplate "text/template"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/time/rate"

	"github.com/Cloud-Foundations/Dominator/lib/log/serverlogger"
	"github.com/Cloud-Foundations/Dominator/lib/logbuf"
	"github.com/Cloud-Foundations/Dominator/lib/srpc"
	"github.com/Cloud-Foundations/golib/pkg/auth/userinfo/gitdb"
	"github.com/Cloud-Foundations/golib/pkg/communications/configuredemail"
	"github.com/Cloud-Foundations/golib/pkg/crypto/certmanager"
	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/golib/pkg/watchdog"
	"github.com/Cloud-Foundations/keymaster/keymasterd/admincache"
	"github.com/Cloud-Foundations/keymaster/keymasterd/eventnotifier"
	compatwebauthn "github.com/Cloud-Foundations/keymaster/lib/compat/webauthn/webauthn"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/paths"
	"github.com/Cloud-Foundations/keymaster/lib/pwauth"
	"github.com/Cloud-Foundations/keymaster/lib/server/aws_identity_cert"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/Cloud-Foundations/keymaster/proto/eventmon"
	"github.com/Cloud-Foundations/tricorder/go/healthserver"
	"github.com/Cloud-Foundations/tricorder/go/tricorder"
	"github.com/Cloud-Foundations/tricorder/go/tricorder/units"
	"github.com/Cloud-Foundations/webauth-sshcert/lib/server/sshcertauth"
	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tstranex/u2f"
)

const (
	AuthTypeNone     = 0
	AuthTypePassword = 1 << iota
	AuthTypeFederated
	AuthTypeU2F
	AuthTypeSymantecVIP
	AuthTypeIPCertificate
	AuthTypeTOTP
	AuthTypeOkta2FA
	AuthTypeBootstrapOTP
	AuthTypeKeymasterX509
	AuthTypeWebauthForCLI
	AuthTypeFIDO2
	AuthTypeSSHCert
)

const (
	AuthTypeAny                   = 0xFFFF
	maxCacheLifetime              = time.Hour
	maxWebauthForCliTokenLifetime = time.Hour * 24 * 366
)

type authInfo struct {
	AuthType     int
	ExpiresAt    time.Time //expiration of auth object
	CertNotAfter time.Time
	Username     string
}

type authInfoJWT struct {
	Issuer       string   `json:"iss,omitempty"`
	Subject      string   `json:"sub,omitempty"`
	Audience     []string `json:"aud,omitempty"`
	Expiration   int64    `json:"exp,omitempty"`
	NotBefore    int64    `json:"nbf,omitempty"`
	IssuedAt     int64    `json:"iat,omitempty"`
	CertNotAfter int64    `json:"cnbt,omitempty"`
	TokenType    string   `json:"token_type"`
	AuthType     int      `json:"auth_type"`
}

type storageStringDataJWT struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	Expiration int64    `json:"exp"`
	IssuedAt   int64    `json:"iat,omitempty"`
	TokenType  string   `json:"token_type"`
	DataType   int      `json:"data_type"`
	Data       string   `json:"data"`
}

type u2fAuthData struct {
	Enabled      bool
	CreatedAt    time.Time
	CreatorAddr  string
	Counter      uint32
	Name         string
	Registration *u2f.Registration
}

type webauthAuthData struct {
	Enabled    bool
	CreatedAt  time.Time
	Name       string
	Credential compatwebauthn.Credential
}

type totpAuthData struct {
	Enabled         bool
	CreatedAt       time.Time
	Name            string
	EncryptedSecret [][]byte
	TOTPType        int
	ValidatorAddr   string
}

type bootstrapOTPData struct {
	ExpiresAt  time.Time
	Sha512Hash []byte
}

type userProfile struct {
	U2fAuthData                map[int64]*u2fAuthData
	RegistrationChallenge      *u2f.Challenge
	PendingTOTPSecret          *[][]byte
	LastSuccessfullTOTPCounter int64
	TOTPAuthData               map[int64]*totpAuthData
	BootstrapOTP               bootstrapOTPData
	UserHasRegistered2ndFactor bool

	WebauthnData map[int64]*webauthAuthData
	WebauthnID   uint64 // maybe more specific?
	DisplayName  string
	Username     string
	// TODO: find a way to serialize-encrypt this
	//WebauthnSessionData *compatwebauthn.SessionData
}

const (
	localAuthTypeWebAuthLogin = iota
	localAuthTypeWebAuthRegistration
	localAuthTypeU2fChallenge
)

type localDataKey struct {
	username string
	dataType int
}

type localUserData struct {
	U2fAuthChallenge  *u2f.Challenge
	WebAuthnChallenge *webauthn.SessionData
	ExpiresAt         time.Time
	WebAuthLogin      *webauthn.SessionData
}

type pendingAuth2Request struct {
	ctx              context.Context
	ExpiresAt        time.Time
	loginDestination string
	state            string
}

type pushPollTransaction struct {
	ExpiresAt     time.Time
	Username      string
	TransactionID string
}

type totpRateLimitInfo struct {
	lastCheckTime         time.Time
	failCount             uint32
	lastFailTime          time.Time
	lockoutExpirationTime time.Time
}

type RuntimeState struct {
	Config                       AppConfigFile
	SSHCARawFileContent          []byte
	Signer                       crypto.Signer
	Ed25519CAFileContent         []byte
	Ed25519Signer                crypto.Signer
	ClientCAPool                 *x509.CertPool
	HostIdentity                 string
	KerberosRealm                *string
	caCertDer                    [][]byte
	selfRoleCaCertDer            []byte
	certManager                  *certmanager.CertificateManager
	vipPushCookie                map[string]pushPollTransaction
	localAuthData                map[localDataKey]localUserData
	SignerIsReady                chan bool
	oktaUsernameFilterRE         *regexp.Regexp
	passwordAttemptGlobalLimiter *rate.Limiter
	Mutex                        sync.Mutex
	gitDB                        *gitdb.UserInfo
	pendingOauth2                map[string]pendingAuth2Request
	storageRWMutex               sync.RWMutex
	db                           *sql.DB
	dbType                       string
	cacheDB                      *sql.DB
	dbDone                       chan struct{}
	remoteDBQueryTimeout         time.Duration
	htmlTemplate                 *htmltemplate.Template
	passwordChecker              pwauth.PasswordAuthenticator
	KeymasterPublicKeys          []crypto.PublicKey
	isAdminCache                 *admincache.Cache
	emailManager                 configuredemail.EmailManager
	textTemplates                *texttemplate.Template
	awsCertIssuer                *aws_identity_cert.Issuer
	webAuthn                     *webauthn.WebAuthn
	fidoMDS                      metadata.Provider
	totpLocalRateLimit           map[string]totpRateLimitInfo
	totpLocalTateLimitMutex      sync.Mutex
	websshauthenticator          *sshcertauth.Authenticator
	logger                       log.DebugLogger
}

const redirectPath = "/auth/oauth2/callback"
const secsBetweenCleanup = 30
const maxAgeU2FVerifySeconds = 30

var (
	Version        = ""
	configFilename = flag.String("config", "/etc/keymaster/config.yml",
		"The filename of the configuration")
	generateConfig = flag.Bool("generateConfig", false,
		"Generate new valid configuration")
	u2fAppID         = "https://www.example.com:33443"
	u2fTrustedFacets = []string{}

	metricsMutex   = &sync.Mutex{}
	certGenCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "keymaster_certificate_issuance_counter",
			Help: "Keymaster certificate issuance counter.",
		},
		[]string{"username", "type"},
	)
	authOperationCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "keymaster_auth_operation_counter",
			Help: "Keymaster_auth_operation_counter",
		},
		[]string{"client_type", "type", "result"},
	)
	passwordRateLimitExceededCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "keymaster_password_rate_limit_exceeded_counter",
			Help: "keymaster_password_rate_limit_exceeded_counter",
		},
		[]string{"username"},
	)

	externalServiceDurationTotal = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "keymaster_external_service_request_duration",
			Help:    "Total amount of time spent non-errored external checks in ms",
			Buckets: []float64{5, 7.5, 10, 15, 25, 50, 75, 100, 150, 250, 500, 750, 1000, 1500, 2500, 5000},
		},
		[]string{"service_name"},
	)
	tricorderLDAPExternalServiceDurationTotal    = tricorder.NewGeometricBucketer(5, 5000.0).NewCumulativeDistribution()
	tricorderStorageExternalServiceDurationTotal = tricorder.NewGeometricBucketer(1, 2000.0).NewCumulativeDistribution()
	tricorderVIPExternalServiceDurationTotal     = tricorder.NewGeometricBucketer(5, 5000.0).NewCumulativeDistribution()

	certDurationHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "keymaster_cert_duration",
			Help:    "Duration of certs in seconds",
			Buckets: []float64{15, 30, 60, 120, 300, 600, 3600, 7200, 36000, 57600, 72000, 86400, 172800},
		},
		[]string{"cert_type", "stage"},
	)

	logger log.DebugLogger
	// TODO(rgooch): Pass this in rather than use a global variable.
	eventNotifier *eventnotifier.EventNotifier
)

//go:embed data/*
var compiledData embed.FS

// This function is just to "remove" the /data path of the embeddedFS
func getCompiledDataFS() http.FileSystem {
	fsys, err := fs.Sub(compiledData, "data")
	if err != nil {
		logger.Fatal(err)
	}
	return http.FS(fsys)
}

type httpLogger struct {
	AccessLogger log.DebugLogger
}

func (l httpLogger) Log(record instrumentedwriter.LogRecord) {
	if l.AccessLogger != nil {
		l.AccessLogger.Printf("%s -  %s [%s] \"%s %s %s\" %d %d \"%s\"\n",
			record.Ip, record.Username, record.Time, record.Method,
			record.Uri, record.Protocol, record.Status, record.Size, record.UserAgent)
	}
}

func (state *RuntimeState) setupServiceMux() (*http.ServeMux, error) {

	var err error
	serviceMux := http.NewServeMux()
	serviceMux.HandleFunc(certgenPath, state.certGenHandler)
	serviceMux.HandleFunc(publicPath, state.publicPathHandler)
	serviceMux.HandleFunc(proto.LoginPath, state.loginHandler)
	serviceMux.HandleFunc(logoutPath, state.logoutHandler)
	serviceMux.HandleFunc(profilePath, state.profileHandler)
	serviceMux.HandleFunc(usersPath, state.usersHandler)
	serviceMux.HandleFunc(addUserPath, state.addUserHandler)
	serviceMux.HandleFunc(deleteUserPath, state.deleteUserHandler)
	//TODO: should enable only if bootraptop is enabled
	serviceMux.HandleFunc(generateBoostrapOTPPath,
		state.generateBootstrapOTP)

	serviceMux.HandleFunc(idpOpenIDCConfigurationDocumentPath,
		state.idpOpenIDCDiscoveryHandler)
	serviceMux.HandleFunc(idpOpenIDCJWKSPath,
		state.idpOpenIDCJWKSHandler)
	serviceMux.HandleFunc(idpOpenIDCAuthorizationPath,
		state.idpOpenIDCAuthorizationHandler)
	serviceMux.HandleFunc(idpOpenIDCTokenPath,
		state.idpOpenIDCTokenHandler)
	serviceMux.HandleFunc(idpOpenIDCUserinfoPath,
		state.idpOpenIDCUserinfoHandler)

	staticFilesPath :=
		filepath.Join(state.Config.Base.SharedDataDirectory,
			"static_files")
	serviceMux.Handle("/static/", cacheControlHandler(
		http.StripPrefix("/static/",
			http.FileServer(http.Dir(staticFilesPath)))))
	serviceMux.Handle("/static/compiled/", cacheControlHandler(
		http.StripPrefix("/static/compiled/",
			http.FileServer(getCompiledDataFS()))))
	customWebResourcesPath :=
		filepath.Join(state.Config.Base.SharedDataDirectory,
			"customization_data", "web_resources")
	if _, err = os.Stat(customWebResourcesPath); err == nil {
		serviceMux.Handle("/custom_static/", cacheControlHandler(
			http.StripPrefix("/custom_static/",
				http.FileServer(http.Dir(customWebResourcesPath)))))
	}

	serviceMux.HandleFunc(u2fRegustisterRequestPath,
		state.u2fRegisterRequest)
	serviceMux.HandleFunc(u2fRegisterRequesponsePath,
		state.u2fRegisterResponse)
	serviceMux.HandleFunc(u2fSignRequestPath, state.u2fSignRequest)
	serviceMux.HandleFunc(u2fSignResponsePath, state.u2fSignResponse)
	serviceMux.HandleFunc(webAutnRegististerRequestPath, state.webauthnBeginRegistration)
	serviceMux.HandleFunc(webAutnRegististerFinishPath, state.webauthnFinishRegistration)
	serviceMux.HandleFunc(webAuthnAuthBeginPath, state.webauthnAuthLogin)
	serviceMux.HandleFunc(webAuthnAuthFinishPath, state.webauthnAuthFinish)

	serviceMux.HandleFunc(vipAuthPath, state.VIPAuthHandler)
	serviceMux.HandleFunc(u2fTokenManagementPath,
		state.u2fTokenManagerHandler)
	serviceMux.HandleFunc(oauth2LoginBeginPath,
		state.oauth2DoRedirectoToProviderHandler)
	serviceMux.HandleFunc(redirectPath, state.oauth2RedirectPathHandler)
	serviceMux.HandleFunc(clientConfHandlerPath,
		state.serveClientConfHandler)
	serviceMux.HandleFunc(vipPushStartPath, state.vipPushStartHandler)
	serviceMux.HandleFunc(vipPollCheckPath, state.VIPPollCheckHandler)
	serviceMux.HandleFunc(totpGeneratNewPath, state.GenerateNewTOTP)
	serviceMux.HandleFunc(totpValidateNewPath, state.validateNewTOTP)
	serviceMux.HandleFunc(totpTokenManagementPath,
		state.totpTokenManagerHandler)
	serviceMux.HandleFunc(totpVerifyHandlerPath, state.verifyTOTPHandler)
	serviceMux.HandleFunc(totpAuthPath, state.TOTPAuthHandler)
	if state.Config.Okta.Domain != "" {
		serviceMux.HandleFunc(okta2FAauthPath, state.Okta2FAuthHandler)
		serviceMux.HandleFunc(oktaPushStartPath,
			state.oktaPushStartHandler)
		serviceMux.HandleFunc(oktaPollCheckPath,
			state.oktaPollCheckHandler)
	}

	if state.checkAwsRolesEnabled() {
		serviceMux.HandleFunc(paths.RequestAwsRoleCertificatePath,
			state.requestAwsRoleCertificateHandler)
	}
	// TODO(rgooch): Condition this on whether Bootstrap OTP is configured.
	//               The inline calls to getRequiredWebUIAuthLevel() should be
	//               moved to the config section and replaced with a simple
	//               bitfield test.
	serviceMux.HandleFunc(bootstrapOtpAuthPath,
		state.BootstrapOtpAuthHandler)
	if state.Config.Base.WebauthTokenForCliLifetime > 0 {
		serviceMux.HandleFunc(paths.SendAuthDocument,
			state.SendAuthDocumentHandler)
		serviceMux.HandleFunc(paths.ShowAuthToken,
			state.ShowAuthTokenHandler)
		serviceMux.HandleFunc(paths.VerifyAuthToken,
			state.VerifyAuthTokenHandler)
	}
	serviceMux.HandleFunc(getRoleRequestingPath, state.roleRequetingCertGenHandler)
	serviceMux.HandleFunc(refreshRoleRequestingCertPath, state.refreshRoleRequestingCertGenHandler)
	serviceMux.HandleFunc("/", state.defaultPathHandler)

	return serviceMux, nil
}

func Usage() {
	displayVersion := Version
	if Version == "" {
		displayVersion = "No version provided"
	}
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], displayVersion)
	flag.PrintDefaults()
}

func init() {
	prometheus.MustRegister(certGenCounter)
	prometheus.MustRegister(authOperationCounter)
	prometheus.MustRegister(passwordRateLimitExceededCounter)
	prometheus.MustRegister(externalServiceDurationTotal)
	prometheus.MustRegister(certDurationHistogram)
	tricorder.RegisterMetric(
		"keymaster/external-service-duration/LDAP",
		tricorderLDAPExternalServiceDurationTotal,
		units.Millisecond,
		"Time for external LDAP server to perform operation(ms)")
	tricorder.RegisterMetric(
		"keymaster/external-service-duration/VIP",
		tricorderVIPExternalServiceDurationTotal,
		units.Millisecond,
		"Time for external VIP server to perform operation(ms)")
	tricorder.RegisterMetric(
		"keymaster/external-service-duration/storage",
		tricorderStorageExternalServiceDurationTotal,
		units.Millisecond,
		"Time for external Storage server to perform operation(ms)")
}

func main() {
	flag.Usage = Usage
	flag.Parse()

	tricorder.RegisterFlags()
	realLogger := serverlogger.New("")
	logger = realLogger

	if *generateConfig {
		err := generateNewConfig(*configFilename)
		if err != nil {
			panic(err)
		}
		return
	}

	// TODO(rgooch): Pass this in rather than use a global variable.
	eventNotifier = eventnotifier.New(logger)
	runtimeState, err := loadVerifyConfigFile(*configFilename, logger)
	if err != nil {
		logger.Println(err)
		os.Exit(1)
	}
	logger.Debugf(3, "After load verify")

	publicLogs := runtimeState.Config.Base.PublicLogs
	adminDashboard := newAdminDashboard(realLogger, publicLogs)

	logBufOptions := logbuf.GetStandardOptions()
	accessLogDirectory := filepath.Join(logBufOptions.Directory, "access")
	logger.Debugf(1, "accesslogdir=%s\n", accessLogDirectory)
	serviceAccessLogger := serverlogger.NewWithOptions("access",
		logbuf.Options{MaxFileSize: 10 << 20,
			Quota: 100 << 20, MaxBufferLines: 100,
			Directory: accessLogDirectory},
		stdlog.LstdFlags)

	adminAccesLogDirectory := filepath.Join(logBufOptions.Directory, "access-admin")
	adminAccessLogger := serverlogger.NewWithOptions("access-admin",
		logbuf.Options{MaxFileSize: 10 << 20,
			Quota: 100 << 20, MaxBufferLines: 100,
			Directory: adminAccesLogDirectory},
		stdlog.LstdFlags)

	// Expose the registered metrics via HTTP.
	http.Handle("/", adminDashboard)
	http.Handle("/prometheus_metrics", promhttp.Handler()) //lint:ignore SA1019 TODO: newer prometheus handler
	http.HandleFunc(secretInjectorPath, runtimeState.secretInjectorHandler)
	http.HandleFunc(readyzPath, runtimeState.readyzHandler)

	serviceMux, err := runtimeState.setupServiceMux()
	if err != nil {
		panic(err)
	}

	cfg := &tls.Config{
		ClientCAs:      runtimeState.ClientCAPool,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		GetCertificate: runtimeState.certManager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256,
			tls.X25519, tls.X25519MLKEM768},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
	}
	logFilterHandler := NewLogFilterHandler(http.DefaultServeMux, publicLogs,
		runtimeState)
	serviceHTTPLogger := httpLogger{AccessLogger: serviceAccessLogger}
	adminHTTPLogger := httpLogger{AccessLogger: adminAccessLogger}
	adminSrv := &http.Server{
		Addr:         runtimeState.Config.Base.AdminAddress,
		TLSConfig:    cfg,
		Handler:      instrumentedwriter.NewLoggingHandler(logFilterHandler, adminHTTPLogger),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	srpc.RegisterServerTlsConfig(
		&tls.Config{ClientCAs: runtimeState.ClientCAPool, MinVersion: tls.VersionTLS12},
		true)
	go func() {
		err := adminSrv.ListenAndServeTLS("", "")
		if err != nil {
			panic(err)
		}

	}()
	if runtimeState.Config.Watchdog.CheckInterval > 0 {
		_, err := watchdog.New(runtimeState.Config.Watchdog, logger)
		if err != nil {
			logger.Fatalln(err)
		}
	}
	isReady := <-runtimeState.SignerIsReady
	if isReady != true {
		panic("got bad signer ready data")
	}

	if len(runtimeState.Config.Ldap.LDAPTargetURLs) > 0 && !runtimeState.Config.Ldap.DisablePasswordCache {
		err = runtimeState.passwordChecker.UpdateStorage(runtimeState)
		if err != nil {
			logger.Fatalf("Cannot update password checker")
		}
	}
	if runtimeState.ClientCAPool == nil {
		runtimeState.ClientCAPool = x509.NewCertPool()
	}
	for _, derCert := range runtimeState.caCertDer {
		myCert, err := x509.ParseCertificate(derCert)
		if err != nil {
			panic(err)
		}
		runtimeState.ClientCAPool.AddCert(myCert)
	}
	parsedCert, err := x509.ParseCertificate(runtimeState.selfRoleCaCertDer)
	if err != nil {
		panic(err)
	}
	runtimeState.ClientCAPool.AddCert(parsedCert)

	// Safari in MacOS 10.12.x required a cert to be presented by the user even
	// when optional.
	// Our usage shows this is less than 1% of users so we are now mandating
	// verification on issues we will need to update clientAuth back  to tls.RequestClientCert
	serviceTLSConfig := &tls.Config{
		ClientCAs:      runtimeState.ClientCAPool,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		GetCertificate: runtimeState.certManager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256,
			tls.X25519, tls.X25519MLKEM768},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
	}
	serviceSrv := &http.Server{
		Addr:         runtimeState.Config.Base.HttpAddress,
		Handler:      instrumentedwriter.NewLoggingHandler(serviceMux, serviceHTTPLogger),
		TLSConfig:    serviceTLSConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	http.Handle(eventmon.HttpPath, eventNotifier)
	go func() {
		time.Sleep(time.Millisecond * 10)
		healthserver.SetReady()
		adminDashboard.setReady()
	}()
	err = serviceSrv.ListenAndServeTLS("", "")
	if err != nil {
		panic(err)
	}
}
