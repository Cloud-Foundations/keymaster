package main

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	htmltemplate "html/template"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	"github.com/Cloud-Foundations/keymaster/lib/authenticators/okta"
	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/paths"
	"github.com/Cloud-Foundations/keymaster/lib/pwauth"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/Cloud-Foundations/keymaster/proto/eventmon"
	"github.com/Cloud-Foundations/tricorder/go/healthserver"
	"github.com/Cloud-Foundations/tricorder/go/tricorder"
	"github.com/Cloud-Foundations/tricorder/go/tricorder/units"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/duo-labs/webauthn/webauthn"
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
)

const (
	AuthTypeAny                   = 0xFFFF
	maxCacheLifetime              = time.Hour
	maxWebauthForCliTokenLifetime = time.Hour * 24 * 366
)

type authInfo struct {
	AuthType  int
	ExpiresAt time.Time
	IssuedAt  time.Time
	Username  string
}

type authInfoJWT struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	Expiration int64    `json:"exp,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	TokenType  string   `json:"token_type"`
	AuthType   int      `json:"auth_type"`
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
	Credential webauthn.Credential
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

	// We will be using this later... but we cannot land this yet
	// because we dont want to polute our address space
	//WebauthnData        map[int64]*webauthAuthData
	WebauthnID          uint64 // maybe more specific?
	DisplayName         string
	Username            string
	WebauthnSessionData *webauthn.SessionData
}

type localUserData struct {
	U2fAuthChallenge  *u2f.Challenge
	WebAuthnChallenge *webauthn.SessionData
	ExpiresAt         time.Time
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
	caCertDer                    []byte
	certManager                  *certmanager.CertificateManager
	vipPushCookie                map[string]pushPollTransaction
	localAuthData                map[string]localUserData
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
	remoteDBQueryTimeout         time.Duration
	htmlTemplate                 *htmltemplate.Template
	passwordChecker              pwauth.PasswordAuthenticator
	KeymasterPublicKeys          []crypto.PublicKey
	isAdminCache                 *admincache.Cache
	emailManager                 configuredemail.EmailManager
	textTemplates                *texttemplate.Template

	webAuthn                *webauthn.WebAuthn
	totpLocalRateLimit      map[string]totpRateLimitInfo
	totpLocalTateLimitMutex sync.Mutex
	logger                  log.DebugLogger
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

func cacheControlHandler(h http.Handler) http.Handler {
	maxAgeSeconds := maxCacheLifetime / time.Second
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control",
			fmt.Sprintf("max-age=%d, public, must-revalidate, proxy-revalidate",
				maxAgeSeconds))
		h.ServeHTTP(w, r)
	})
}

func metricLogAuthOperation(clientType string, authType string, success bool) {
	validStr := strconv.FormatBool(success)
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	authOperationCounter.WithLabelValues(clientType, authType, validStr).Inc()
}

func metricLogExternalServiceDuration(service string, duration time.Duration) {
	val := duration.Seconds() * 1000
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	externalServiceDurationTotal.WithLabelValues(service).Observe(val)
	switch service {
	case "ldap":
		tricorderLDAPExternalServiceDurationTotal.Add(duration)
	case "vip":
		tricorderVIPExternalServiceDurationTotal.Add(duration)
	case "storage-read":
		tricorderStorageExternalServiceDurationTotal.Add(duration)
	case "storage-save":
		tricorderStorageExternalServiceDurationTotal.Add(duration)
	}
}

func metricLogCertDuration(certType string, stage string, val float64) {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	certDurationHistogram.WithLabelValues(certType, stage).Observe(val)
}

func getHostIdentity() (string, error) {
	return os.Hostname()
}

func exitsAndCanRead(fileName string, description string) ([]byte, error) {
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return nil, err
	}
	buffer, err := ioutil.ReadFile(fileName)
	if err != nil {
		err = errors.New("cannot read " + description + "file")
		return nil, err
	}
	return buffer, err
}

func getSignerFromPEMBytes(privateKey []byte) (crypto.Signer, error) {
	return certgen.GetSignerFromPEMBytes(privateKey)
}

// Assumes the runtime state signer has been loaded!
func generateCADer(state *RuntimeState, keySigner crypto.Signer) ([]byte, error) {
	organizationName := state.HostIdentity
	if state.KerberosRealm != nil {
		organizationName = *state.KerberosRealm
	}
	return certgen.GenSelfSignedCACert(state.HostIdentity, organizationName, keySigner)
}

func (state *RuntimeState) performStateCleanup(secsBetweenCleanup int) {
	for {
		state.Mutex.Lock()
		//
		initPendingSize := len(state.pendingOauth2)
		for key, oauth2Pending := range state.pendingOauth2 {
			if oauth2Pending.ExpiresAt.Before(time.Now()) {
				delete(state.pendingOauth2, key)
			}
		}
		finalPendingSize := len(state.pendingOauth2)

		//localAuthData
		initPendingLocal := len(state.localAuthData)
		for key, localAuth := range state.localAuthData {
			if localAuth.ExpiresAt.Before(time.Now()) {
				delete(state.localAuthData, key)
			}
		}
		finalPendingLocal := len(state.localAuthData)

		for key, vipCookie := range state.vipPushCookie {
			if vipCookie.ExpiresAt.Before(time.Now()) {
				delete(state.vipPushCookie, key)
			}

		}

		state.Mutex.Unlock()
		logger.Debugf(3, "Pending Cookie sizes: before(%d) after(%d)",
			initPendingSize, finalPendingSize)
		logger.Debugf(3, "Pending Cookie sizes: before(%d) after(%d)",
			initPendingLocal, finalPendingLocal)
		time.Sleep(time.Duration(secsBetweenCleanup) * time.Second)
	}

}

func convertToBindDN(username string, bind_pattern string) string {
	return fmt.Sprintf(bind_pattern, username)
}

func checkUserPassword(username string, password string, config AppConfigFile,
	passwordChecker pwauth.PasswordAuthenticator,
	r *http.Request) (bool, error) {
	clientType := getClientType(r)
	if passwordChecker != nil {
		logger.Debugf(3, "checking auth with passwordChecker")
		isLDAP := false
		if len(config.Ldap.LDAPTargetURLs) > 0 {
			isLDAP = true
		}
		start := time.Now()
		valid, err := passwordChecker.PasswordAuthenticate(username,
			[]byte(password))
		if err != nil {
			return false, err
		}
		// TODO: Replace these if's by a type switch
		if isLDAP {
			metricLogExternalServiceDuration("ldap", time.Since(start))
		}
		_, isOktaPwAuth := passwordChecker.(*okta.PasswordAuthenticator)
		if isOktaPwAuth {
			metricLogExternalServiceDuration("okta-passwd", time.Since(start))
		}
		logger.Debugf(3, "pwdChecker output = %d", valid)
		metricLogAuthOperation(clientType, "password", valid)
		return valid, nil
	}
	metricLogAuthOperation(clientType, "password", false)
	return false, nil
}

// returns application/json or text/html depending on the request. By default we assume the requester wants json
func getPreferredAcceptType(r *http.Request) string {
	preferredAcceptType := "application/json"
	acceptHeader, ok := r.Header["Accept"]
	if ok {
		for _, acceptValue := range acceptHeader {
			if strings.Contains(acceptValue, "text/html") {
				logger.Debugf(1, "Got it  %+v", acceptValue)
				preferredAcceptType = "text/html"
			}
		}
	}
	return preferredAcceptType
}

func browserSupportsU2F(r *http.Request) bool {
	if strings.Contains(r.UserAgent(), "Chrome/") {
		return true
	}
	if strings.Contains(r.UserAgent(), "Presto/") {
		return true
	}
	if strings.Contains(r.UserAgent(), "Firefox/") {
		return true
	}
	return false
}

func getClientType(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	preferredAcceptType := getPreferredAcceptType(r)
	switch preferredAcceptType {
	case "text/html":
		return "browser"
	case "application/json":
		if len(r.Referer()) > 1 {
			return "browser"
		}
		return "cli"
	default:
		return "unknown"
	}
}

// getOriginOrReferrer will return the value of the "Origin" header, or if
// empty, the Referrer (misspelled as "Referer" in the HTML standards).
func getOriginOrReferrer(r *http.Request) string {
	if origin := r.Header.Get("Origin"); origin != "" {
		return origin
	}
	return r.Referer()
}

// getUser will return the "user" value from the request form. If the username
// contains invalid characters, the empty string is returned.
func getUserFromRequest(r *http.Request) string {
	user := r.Form.Get("user")
	if user == "" {
		return ""
	}
	if m, _ := regexp.MatchString("^[-.a-zA-Z0-9_+]+$", user); !m {
		return ""
	}
	return user
}

func (ai *authInfo) expires() int64 {
	if ai.ExpiresAt.IsZero() {
		return 0
	}
	return ai.ExpiresAt.Unix()
}

func ensureHTMLSafeLoginDestination(loginDestination string) string {
	if loginDestination == "" {
		return profilePath
	}
	parsedLoginDestination, err := url.Parse(loginDestination)
	if err != nil {
		return profilePath
	}
	return parsedLoginDestination.String()

}

// checkPasswordAttemptLimit will check if the limit on password attempts has
// been reached. If the limit has been reached, an error response is written to
// w and an error message is returned.
func (state *RuntimeState) checkPasswordAttemptLimit(w http.ResponseWriter,
	r *http.Request, username string) error {
	if !state.passwordAttemptGlobalLimiter.Allow() {
		state.writeFailureResponse(w, r, http.StatusTooManyRequests,
			"Too many password attempts")
		passwordRateLimitExceededCounter.WithLabelValues(username).Inc()
		return fmt.Errorf("too many password attempts, host: %s user: %s",
			r.RemoteAddr, username)
	}
	return nil
}

func (state *RuntimeState) writeHTML2FAAuthPage(w http.ResponseWriter,
	r *http.Request, loginDestination string, tryShowU2f bool,
	showBootstrapOTP bool) error {
	JSSources := []string{"/static/jquery-3.5.1.min.js", "/static/u2f-api.js"}
	showU2F := browserSupportsU2F(r) && tryShowU2f
	if showU2F {
		JSSources = append(JSSources, "/static/webui-2fa-u2f.js")
	}
	if state.Config.SymantecVIP.Enabled {
		JSSources = append(JSSources, "/static/webui-2fa-symc-vip.js")
	}
	if state.Config.Okta.Enable2FA {
		JSSources = append(JSSources, "/static/webui-2fa-okta-push.js")
	}
	safeLoginDestination := ensureHTMLSafeLoginDestination(loginDestination)
	displayData := secondFactorAuthTemplateData{
		Title:                 "Keymaster 2FA Auth",
		JSSources:             JSSources,
		ShowBootstrapOTP:      showBootstrapOTP,
		ShowVIP:               state.Config.SymantecVIP.Enabled,
		ShowU2F:               showU2F,
		ShowTOTP:              state.Config.Base.EnableLocalTOTP,
		ShowOktaOTP:           state.Config.Okta.Enable2FA,
		LoginDestinationInput: htmltemplate.HTML("<INPUT TYPE=\"hidden\" id=\"login_destination_input\" NAME=\"login_destination\" VALUE=\"" + safeLoginDestination + "\">"),
	}
	err := state.htmlTemplate.ExecuteTemplate(w, "secondFactorLoginPage",
		displayData)
	if err != nil {
		logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return err
	}
	return nil
}

func (state *RuntimeState) writeHTMLLoginPage(w http.ResponseWriter,
	r *http.Request, statusCode int,
	defaultUsername, loginDestination, errorMessage string) {
	showBasicAuth := true
	if state.Config.Oauth2.Enabled &&
		(state.Config.Oauth2.ForceRedirect || state.passwordChecker == nil) {
		showBasicAuth = false
	}
	w.WriteHeader(statusCode)

	safeLoginDestination := ensureHTMLSafeLoginDestination(loginDestination)
	displayData := loginPageTemplateData{
		Title:                 "Keymaster Login",
		DefaultUsername:       defaultUsername,
		ShowBasicAuth:         showBasicAuth,
		ShowOauth2:            state.Config.Oauth2.Enabled,
		LoginDestinationInput: htmltemplate.HTML("<INPUT TYPE=\"hidden\" id=\"login_destination_input\" NAME=\"login_destination\" VALUE=\"" + safeLoginDestination + "\">"),
		ErrorMessage:          errorMessage,
	}
	err := state.htmlTemplate.ExecuteTemplate(w, "loginPage", displayData)
	if err != nil {
		logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

func (state *RuntimeState) writeFailureResponse(w http.ResponseWriter,
	r *http.Request, code int, message string) {
	publicErrorText := fmt.Sprintf("%d %s %s\n",
		code, http.StatusText(code), message)
	setSecurityHeaders(w)
	// Do not do any magic if the request is not on the service port. This
	// prevents login redirects on the admin port.
	_, httpPort, err := net.SplitHostPort(state.Config.Base.HttpAddress)
	if err == nil {
		_, reqPort, err := net.SplitHostPort(r.Host)
		if err == nil && reqPort != httpPort {
			http.Error(w, publicErrorText, code)
			return
		}
	}
	returnAcceptType := getPreferredAcceptType(r)
	if code == http.StatusUnauthorized && returnAcceptType != "text/html" {
		w.Header().Set("WWW-Authenticate", `Basic realm="User Credentials"`)
	}
	switch code {
	case http.StatusUnauthorized:
		switch returnAcceptType {
		case "text/html":
			var authCookie *http.Cookie
			for _, cookie := range r.Cookies() {
				if cookie.Name != authCookieName {
					continue
				}
				authCookie = cookie
			}
			loginDestination := profilePath
			switch r.URL.Path {
			case idpOpenIDCAuthorizationPath, paths.ShowAuthToken,
				paths.SendAuthDocument:
				loginDestination = r.URL.String()
			}
			if r.Method == "POST" {
				/// assume it has been parsed... otherwise why are we here?
				if r.Form.Get("login_destination") != "" {
					loginDestination = getLoginDestination(r)
				}
			}
			if authCookie == nil {
				// TODO: change by a message followed by an HTTP redirection
				state.writeHTMLLoginPage(w, r, code, getUserFromRequest(r),
					loginDestination, message)
				return
			}
			info, err := state.getAuthInfoFromAuthJWT(authCookie.Value)
			if err != nil {
				logger.Debugf(3,
					"write failure state, error from getinfo authInfoJWT")
				state.writeHTMLLoginPage(w, r, code, getUserFromRequest(r),
					loginDestination, "")
				return
			}
			if info.ExpiresAt.Before(time.Now()) {
				state.writeHTMLLoginPage(w, r, code, getUserFromRequest(r),
					loginDestination, "")
				return
			}
			if (info.AuthType & AuthTypePassword) == AuthTypePassword {
				state.writeHTML2FAAuthPage(w, r, loginDestination, true, false)
				return
			}
			if (info.AuthType & AuthTypeFederated) == AuthTypeFederated {
				state.writeHTML2FAAuthPage(w, r, loginDestination, true, false)
				return
			}
			state.writeHTMLLoginPage(w, r, code, getUserFromRequest(r),
				loginDestination, message)
			return
		default:
			w.WriteHeader(code)
			w.Write([]byte(publicErrorText))
		}
	default:
		w.WriteHeader(code)
		w.Write([]byte(publicErrorText))
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	//all common security headers go here
	w.Header().Set("Strict-Transport-Security", "max-age=1209600")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1")
	w.Header().Set("Content-Security-Policy", "default-src 'self' ;style-src 'self' fonts.googleapis.com 'unsafe-inline'; font-src fonts.gstatic.com fonts.googleapis.com")
}

// returns true if the system is locked and sends message to the requester
func (state *RuntimeState) sendFailureToClientIfLocked(w http.ResponseWriter, r *http.Request) bool {
	var signerIsNull bool

	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	state.Mutex.Unlock()

	setSecurityHeaders(w)

	if signerIsNull {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer has not been unlocked")
		return true
	}
	return false
}

func (state *RuntimeState) setNewAuthCookie(w http.ResponseWriter,
	username string, authlevel int) (string, error) {
	cookieVal, err := state.genNewSerializedAuthJWT(username, authlevel,
		maxAgeSecondsAuthCookie)
	if err != nil {
		logger.Println(err)
		return "", err
	}
	expiration := time.Now().Add(time.Duration(maxAgeSecondsAuthCookie) *
		time.Second)
	authCookie := http.Cookie{
		Name:    authCookieName,
		Value:   cookieVal,
		Expires: expiration,
		Path:    "/", HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	//use handler with original request.
	if w != nil {
		http.SetCookie(w, &authCookie)
	}
	return cookieVal, nil
}

func (state *RuntimeState) updateAuthCookieAuthlevel(w http.ResponseWriter, r *http.Request, authlevel int) (string, error) {
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}
	if authCookie == nil {
		err := errors.New("cannot find authCookie")
		return "", err
	}

	var err error
	cookieVal, err := state.updateAuthJWTWithNewAuthLevel(authCookie.Value, authlevel)
	if err != nil {
		return "", err
	}

	updatedAuthCookie := http.Cookie{Name: authCookieName, Value: cookieVal, Expires: authCookie.Expires, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode}
	logger.Debugf(3, "about to update authCookie")
	http.SetCookie(w, &updatedAuthCookie)
	return authCookie.Value, nil
}
func (state *RuntimeState) isAutomationUser(username string) (bool, error) {
	for _, automationUsername := range state.Config.Base.AutomationUsers {
		if automationUsername == username {
			return true, nil
		}
	}
	userGroups, err := state.getUserGroups(username)
	if err != nil {
		return false, err
	}
	for _, automationGroup := range state.Config.Base.AutomationUserGroups {
		for _, groupName := range userGroups {
			if groupName == automationGroup {
				return true, nil
			}
		}
	}
	return false, nil
}

func (state *RuntimeState) getUsernameIfKeymasterSigned(VerifiedChains [][]*x509.Certificate) (string, time.Time, error) {
	for _, chain := range VerifiedChains {
		if len(chain) < 2 {
			continue
		}
		username := chain[0].Subject.CommonName
		//keymaster certs as signed directly
		certSignerPKFingerprint, err := getKeyFingerprint(chain[1].PublicKey)
		if err != nil {
			return "", time.Time{}, err
		}
		for _, key := range state.KeymasterPublicKeys {
			fp, err := getKeyFingerprint(key)
			if err != nil {
				return "", time.Time{}, err
			}
			if certSignerPKFingerprint == fp {
				return username, chain[0].NotBefore, nil
			}
		}

	}
	return "", time.Time{}, nil
}

func (state *RuntimeState) getUsernameIfIPRestricted(VerifiedChains [][]*x509.Certificate, r *http.Request) (string, time.Time, error, error) {
	clientName := VerifiedChains[0][0].Subject.CommonName
	userCert := VerifiedChains[0][0]

	validIP, err := certgen.VerifyIPRestrictedX509CertIP(userCert, r.RemoteAddr)
	if err != nil {
		logger.Printf("Error verifying up restricted cert: %s", err)
		return "", time.Time{}, nil, err
	}
	if !validIP {
		logger.Printf("Invalid IP for cert: %s is not valid for incoming connection", r.RemoteAddr)
		return "", time.Time{}, fmt.Errorf("Bad incoming ip addres"), nil
	}
	// Check if there are group restrictions on
	ok, err := state.isAutomationUser(clientName)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("checkAuth: Error checking user permissions for automation certs : %s", err)
	}
	if !ok {
		return "", time.Time{}, fmt.Errorf("Bad username  for ip restricted cert"), nil
	}

	revoked, ok, err := revoke.VerifyCertificateError(userCert)
	if err != nil {
		logger.Printf("Error checking revocation of IP  restricted cert: %s", err)
	}
	// Soft Fail: we only fail if the revocation check was successful and the cert is revoked
	if revoked == true && ok {
		logger.Printf("Cert is revoked")
		//state.writeFailureResponse(w, r, http.StatusUnauthorized, "revoked Cert")
		return "", time.Time{}, fmt.Errorf("revoked cert"), nil
	}
	return clientName, time.Now(), nil, nil
}

// Inspired by http://stackoverflow.com/questions/21936332/idiomatic-way-of-requiring-http-basic-auth-in-go
func (state *RuntimeState) checkAuth(w http.ResponseWriter, r *http.Request, requiredAuthType int) (*authInfo, error) {
	// Check csrf
	if r.Method != "GET" {
		referer := getOriginOrReferrer(r)
		if len(referer) > 0 && len(r.Host) > 0 {
			state.logger.Debugf(3, "ref =%s, host=%s", referer, r.Host)
			refererURL, err := url.Parse(referer)
			if err != nil {
				return nil, err
			}
			state.logger.Debugf(3, "refHost =%s, host=%s",
				refererURL.Host, r.Host)
			if refererURL.Host != r.Host {
				state.logger.Printf("CSRF detected.... rejecting with a 400")
				state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
				return nil, errors.New("CSRF detected... rejecting")
			}
		}
	}
	// We first check for certs if this auth is allowed
	if ((requiredAuthType & (AuthTypeIPCertificate | AuthTypeKeymasterX509)) != 0) &&
		r.TLS != nil {
		state.logger.Debugf(3,
			"looks like authtype tls keymaster or ip cert, r.tls=%+v", r.TLS)
		if len(r.TLS.VerifiedChains) > 0 {
			if (requiredAuthType & AuthTypeKeymasterX509) != 0 {
				tlsAuthUser, notBefore, err :=
					state.getUsernameIfKeymasterSigned(r.TLS.VerifiedChains)
				if err == nil && tlsAuthUser != "" {
					return &authInfo{
						AuthType: AuthTypeKeymasterX509,
						IssuedAt: notBefore,
						Username: tlsAuthUser,
					}, nil
				}
			}
			if (requiredAuthType & AuthTypeIPCertificate) != 0 {
				clientName, notBefore, userErr, err :=
					state.getUsernameIfIPRestricted(r.TLS.VerifiedChains, r)
				if userErr != nil {
					state.writeFailureResponse(w, r, http.StatusForbidden,
						fmt.Sprintf("%s", userErr))
					return nil, userErr
				}
				if err != nil {
					state.writeFailureResponse(w, r,
						http.StatusInternalServerError, "")
					return nil, err
				}
				return &authInfo{
					AuthType: AuthTypeIPCertificate,
					IssuedAt: notBefore,
					Username: clientName,
				}, nil
			}
		}
	}
	// Next we check for cookies
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}
	if authCookie == nil {
		if (AuthTypePassword & requiredAuthType) == 0 {
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
			err := errors.New("Insufficient Auth Level passwd")
			return nil, err
		}
		//For now try also http basic (to be deprecated)
		user, pass, ok := r.BasicAuth()
		if !ok {
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
			//toLoginOrBasicAuth(w, r)
			return nil, errors.New("checkAuth, Invalid or no auth header")
		}
		if err := state.checkPasswordAttemptLimit(w, r, user); err != nil {
			return nil, err
		}
		state.Mutex.Lock()
		config := state.Config
		state.Mutex.Unlock()
		user = state.reprocessUsername(user)
		valid, err := checkUserPassword(user, pass, config,
			state.passwordChecker, r)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return nil, err
		}
		if !valid {
			state.writeFailureResponse(w, r, http.StatusUnauthorized,
				"Invalid Username/Password")
			err := errors.New("Invalid Credentials")
			return nil, err
		}
		return &authInfo{
			AuthType: AuthTypePassword,
			IssuedAt: time.Now(),
			Username: user,
		}, nil
	}
	//Critical section
	info, err := state.getAuthInfoFromAuthJWT(authCookie.Value)
	if err != nil {
		//TODO check between internal and bad cookie error
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		err := errors.New("Invalid Cookie")
		return nil, err
	}
	//check for expiration...
	if info.ExpiresAt.Before(time.Now()) {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		err := errors.New("Expired Cookie")
		return nil, err
	}
	if (info.AuthType & requiredAuthType) == 0 {
		state.logger.Debugf(1, "info.AuthType: %v, requiredAuthType: %v\n",
			info.AuthType, requiredAuthType)
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		err := errors.New("Insufficient Auth Level in critical cookie")
		return nil, err
	}
	return &info, nil
}

func (state *RuntimeState) getRequiredWebUIAuthLevel() int {
	AuthLevel := 0
	for _, webUIPref := range state.Config.Base.AllowedAuthBackendsForWebUI {
		if webUIPref == proto.AuthTypePassword {
			AuthLevel |= AuthTypePassword
		}
		if webUIPref == proto.AuthTypeFederated {
			AuthLevel |= AuthTypeFederated
		}
		if webUIPref == proto.AuthTypeU2F {
			AuthLevel |= AuthTypeU2F
		}
		if webUIPref == proto.AuthTypeSymantecVIP {
			AuthLevel |= AuthTypeSymantecVIP
		}
		if webUIPref == proto.AuthTypeTOTP {
			AuthLevel |= AuthTypeTOTP
		}
		if webUIPref == proto.AuthTypeOkta2FA {
			AuthLevel |= AuthTypeOkta2FA
		}
		if webUIPref == proto.AuthTypeBootstrapOTP {
			AuthLevel |= AuthTypeBootstrapOTP
		}
	}
	return AuthLevel
}

func (state *RuntimeState) reprocessUsername(username string) string {
	if !state.Config.Base.DisableUsernameNormalization {
		username = strings.ToLower(username)
	}
	if state.oktaUsernameFilterRE != nil {
		filteredUsername := string(state.oktaUsernameFilterRE.ReplaceAll(
			[]byte(username), nil))
		logger.Debugf(1, "filtered user: \"%s\" to: \"%s\"\n",
			username, filteredUsername)
		username = filteredUsername
	}
	return username
}

const secretInjectorPath = "/admin/inject"
const readyzPath = "/readyz" // Kubernetes convention.

const publicPath = "/public/"

const loginFormPath = "/public/loginForm"

func (state *RuntimeState) publicPathHandler(w http.ResponseWriter, r *http.Request) {
	var signerIsNull bool

	// check if initialized(singer  not nil)
	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	state.Mutex.Unlock()
	if signerIsNull {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer not loaded")
		return
	}

	target := r.URL.Path[len(publicPath):]

	switch target {
	case "loginForm":
		//fmt.Fprintf(w, "%s", loginFormText)
		setSecurityHeaders(w)
		state.writeHTMLLoginPage(w, r, 200, "", profilePath, "")
		return
	case "x509ca":
		pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: state.caCertDer}))

		w.Header().Set("Content-Disposition", `attachment; filename="id_rsa-cert.pub"`)
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", pemCert)
	default:
		state.writeFailureResponse(w, r, http.StatusNotFound, "")
		return
	}
}

func (state *RuntimeState) userHasU2FTokens(username string) (bool, error) {
	profile, ok, _, err := state.LoadUserProfile(username)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	for _, u2fRegistration := range profile.U2fAuthData {
		if u2fRegistration.Enabled {
			return true, nil
		}

	}
	return false, nil

}

const authCookieName = "auth_cookie"
const vipTransactionCookieName = "vip_push_cookie"
const maxAgeSecondsVIPCookie = 120
const randomStringEntropyBytes = 32
const maxAgeSecondsAuthCookie = 16 * 3600

func genRandomString() (string, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(rb), nil
}

// We need to ensure that all login destinations are relative paths
// Thus the path MUST start with a / but MUST NOT start with a //, because
// // is interpreted as: use whatever protocol you think is OK
func getLoginDestination(r *http.Request) string {
	loginDestination := profilePath
	if r.FormValue("login_destination") != "" {
		inboundLoginDestination := r.Form.Get("login_destination")
		if strings.HasPrefix(inboundLoginDestination, "/") &&
			!strings.HasPrefix(inboundLoginDestination, "//") {
			loginDestination = inboundLoginDestination
		}
	}
	return loginDestination
}

//const loginPath = "/api/v0/login"

func (state *RuntimeState) loginHandler(w http.ResponseWriter,
	r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	//Check for valid method here?
	switch r.Method {
	case "GET":
		logger.Debugf(3, "Got client GET connection")
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Error parsing form")
			return
		}
	case "POST":
		logger.Debugf(3, "Got client POST connection")
		//err := r.ParseMultipartForm(1e7)
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Error parsing form")
			return
		}
		logger.Debugf(2, "req =%+v", r)
	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	//First headers and then check form
	username, password, ok := r.BasicAuth()
	if !ok {
		//var username string
		if val, ok := r.Form["username"]; ok {
			if len(val) > 1 {
				state.writeFailureResponse(w, r, http.StatusBadRequest,
					"Just one username allowed")
				logger.Printf("Login with multiple usernames")
				return
			}
			username = val[0]
			// Since we are getting username from Form we need some minimal sanitization
			// TODO: actually whitelist the username characters
			escapedUsername := strings.Replace(username, "\n", "", -1)
			escapedUsername = strings.Replace(escapedUsername, "\r", "", -1)
			username = escapedUsername
		}
		//var password string
		if val, ok := r.Form["password"]; ok {
			if len(val) > 1 {
				state.writeFailureResponse(w, r, http.StatusBadRequest,
					"Just one password allowed")
				logger.Printf("Login with passwords")
				return
			}
			password = val[0]
		}
		if len(username) < 1 || len(password) < 1 {
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
			return
		}
	}
	if err := state.checkPasswordAttemptLimit(w, r, username); err != nil {
		state.logger.Debugf(1, "%v", err)
		return
	}
	username = state.reprocessUsername(username)
	valid, err := checkUserPassword(username, password, state.Config,
		state.passwordChecker, r)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if !valid {
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"Invalid Username/Password")
		logger.Printf("Invalid login for %s", username)
		return
	}
	// AUTHN has passed
	logger.Debugf(1, "Valid passwd AUTH login for %s\n", username)
	userHasU2FTokens, err := state.userHasU2FTokens(username)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		logger.Println(err)
		return
	}
	_, err = state.setNewAuthCookie(w, username, AuthTypePassword)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		logger.Println(err)
		return
	}
	eventNotifier.PublishAuthEvent(eventmon.AuthTypePassword, username)
	returnAcceptType := "application/json"
	acceptHeader, ok := r.Header["Accept"]
	if ok {
		for _, acceptValue := range acceptHeader {
			if strings.Contains(acceptValue, "text/html") {
				logger.Debugf(1, "Got it  %+v", acceptValue)
				returnAcceptType = "text/html"
			}
		}
	}
	profile, _, fromCache, err := state.LoadUserProfile(username)
	if err != nil {
		state.logger.Printf("error loading user profile err=%s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"cannot load user profile")
		return
	}
	if !fromCache {
		state.trySelfServiceGenerateBootstrapOTP(username, profile)
	}
	userHasBootstrapOTP := len(state.userBootstrapOtpHash(profile,
		fromCache)) > 0
	// Compute the cert prefs
	var certBackends []string
	for _, certPref := range state.Config.Base.AllowedAuthBackendsForCerts {
		if certPref == proto.AuthTypePassword {
			certBackends = append(certBackends, proto.AuthTypePassword)
		}
		if certPref == proto.AuthTypeU2F && userHasU2FTokens {
			certBackends = append(certBackends, proto.AuthTypeU2F)
		}
		if certPref == proto.AuthTypeSymantecVIP &&
			state.Config.SymantecVIP.Enabled {
			certBackends = append(certBackends, proto.AuthTypeSymantecVIP)
		}
		if certPref == proto.AuthTypeTOTP && state.Config.Base.EnableLocalTOTP {
			certBackends = append(certBackends, proto.AuthTypeTOTP)
		}
		if certPref == proto.AuthTypeOkta2FA && state.Config.Okta.Enable2FA {
			certBackends = append(certBackends, proto.AuthTypeOkta2FA)
		}
	}
	// logger.Printf("current backends=%+v", certBackends)
	if len(certBackends) == 0 {
		certBackends = append(certBackends, proto.AuthTypeU2F)
	}
	// TODO: The cert backend should depend also on per user preferences.
	loginResponse := proto.LoginResponse{Message: "success",
		CertAuthBackend: certBackends}
	switch returnAcceptType {
	case "text/html":
		loginDestination := getLoginDestination(r)
		requiredAuth := state.getRequiredWebUIAuthLevel()
		if (requiredAuth & AuthTypePassword) != 0 {
			eventNotifier.PublishWebLoginEvent(username)
			http.Redirect(w, r, loginDestination, 302)
		} else {
			//Go 2FA
			if (requiredAuth & AuthTypeSymantecVIP) == AuthTypeSymantecVIP {
				// set VIP cookie
				cookieValue, err := genRandomString()
				if err == nil { //Beware inverted Logic
					expiration := time.Now().Add(maxAgeSecondsVIPCookie *
						time.Second)
					vipPushCookie := http.Cookie{Name: vipTransactionCookieName,
						Value: cookieValue, Expires: expiration,
						Path: "/", HttpOnly: true, Secure: true}
					http.SetCookie(w, &vipPushCookie)
				}
			}
			state.writeHTML2FAAuthPage(w, r, loginDestination, userHasU2FTokens,
				userHasBootstrapOTP)
		}
	default:
		// add vippush cookie if we are using VIP
		usesVIP := false
		for _, certPref := range state.Config.Base.AllowedAuthBackendsForCerts {
			if certPref == proto.AuthTypeSymantecVIP &&
				state.Config.SymantecVIP.Enabled {
				usesVIP = true
			}
		}
		requiredWebAuth := state.getRequiredWebUIAuthLevel()
		usesVIP = usesVIP ||
			((requiredWebAuth & AuthTypeSymantecVIP) == AuthTypeSymantecVIP)
		if usesVIP {
			cookieValue, err := genRandomString()
			if err == nil { //Beware inverted Logic
				expiration := time.Now().Add(maxAgeSecondsVIPCookie *
					time.Second)
				vipPushCookie := http.Cookie{Name: vipTransactionCookieName,
					Value: cookieValue, Expires: expiration,
					Path: "/", HttpOnly: true, Secure: true}
				http.SetCookie(w, &vipPushCookie)
			}
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)
	}
	return
}

const logoutPath = "/api/v0/logout"

func (state *RuntimeState) logoutHandler(w http.ResponseWriter,
	r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	//TODO: check for CSRF (simple way: makeit post only)
	// We first check for cookies
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}
	var loginUser string
	if authCookie != nil {
		info, err := state.getAuthInfoFromAuthJWT(authCookie.Value)
		if err == nil {
			loginUser = info.Username
		}
		expiration := time.Unix(0, 0)
		updatedAuthCookie := http.Cookie{
			Name:     authCookieName,
			Value:    "",
			Expires:  expiration,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		}
		http.SetCookie(w, &updatedAuthCookie)
	}
	//redirect to login
	if loginUser == "" {
		http.Redirect(w, r, "/", 302)
	} else {
		http.Redirect(w, r, fmt.Sprintf("/?user=%s", loginUser), 302)
	}
}

func (state *RuntimeState) _IsAdminUser(user string) (bool, error) {
	for _, adminUser := range state.Config.Base.AdminUsers {
		if user == adminUser {
			return true, nil
		}
	}
	if len(state.Config.Base.AdminGroups) > 0 {
		groups, err := state.getUserGroups(user)
		if err != nil {
			return false, err
		}
		// Store groups to which this user belongs in a set.
		userGroupSet := make(map[string]struct{})
		for _, group := range groups {
			userGroupSet[group] = struct{}{}
		}
		// Check each admin group from config file.
		// If user belongs to one of these groups then they are an admin
		// user.
		for _, adminGroup := range state.Config.Base.AdminGroups {
			if _, ok := userGroupSet[adminGroup]; ok {
				return true, nil
			}
		}
	}
	return false, nil
}

func (state *RuntimeState) IsAdminUser(user string) bool {
	isAdmin, valid := state.isAdminCache.Get(user)

	// If cached entry is valid, return it as is.
	if valid {
		return isAdmin
	}

	// Entry has expired, do expensive _IsAdminUser call
	newIsAdmin, err := state._IsAdminUser(user)
	if err == nil {

		// On success, cache and return result
		state.isAdminCache.Put(user, newIsAdmin)
		return newIsAdmin
	}
	// Otherwise, re-cache and return previously cached value
	state.isAdminCache.Put(user, isAdmin)
	return isAdmin
}

func (state *RuntimeState) IsAdminUserAndU2F(user string, loginLevel int) bool {
	return state.IsAdminUser(user) && ((loginLevel & AuthTypeU2F) != 0)
}

const profilePath = "/profile/"

func profileURI(authUser, assumedUser string) string {
	if authUser == assumedUser {
		return profilePath
	}
	return profilePath + assumedUser
}

func (state *RuntimeState) profileHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	// /profile/<assumed user>
	// pieces[0] == "" pieces[1] = "profile" pieces[2] == <assumed user>
	pieces := strings.Split(r.URL.Path, "/")

	var assumedUser string
	if len(pieces) >= 3 {
		assumedUser = pieces[2]
	}

	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	readOnlyMsg := ""
	if assumedUser == "" {
		assumedUser = authData.Username
	} else if !state.IsAdminUser(authData.Username) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	} else if (authData.AuthType & AuthTypeU2F) == 0 {
		readOnlyMsg = "Admins must U2F authenticate to change the profile of others."
	}

	//find the user token
	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		readOnlyMsg = "The active keymaster is running disconnected from its DB backend. All token operations execpt for Authentication cannot proceed."
	}
	JSSources := []string{
		"/static/jquery-3.5.1.min.js",
		"/static/compiled/session.js",
	}
	showU2F := browserSupportsU2F(r)
	if showU2F {
		JSSources = append(JSSources, "/static/u2f-api.js", "/static/keymaster-u2f.js", "/static/keymaster-webauthn.js")
	}

	// TODO: move deviceinfo mapping/sorting to its own function
	var u2fdevices []registeredU2FTokenDisplayInfo
	for i, tokenInfo := range profile.U2fAuthData {
		deviceData := registeredU2FTokenDisplayInfo{
			DeviceData: fmt.Sprintf("%+v", tokenInfo.Registration.AttestationCert.Subject.CommonName),
			Enabled:    tokenInfo.Enabled,
			Name:       tokenInfo.Name,
			Index:      i}
		u2fdevices = append(u2fdevices, deviceData)
	}

	sort.Slice(u2fdevices, func(i, j int) bool {
		if u2fdevices[i].Name < u2fdevices[j].Name {
			return true
		}
		if u2fdevices[i].Name > u2fdevices[j].Name {
			return false
		}
		return u2fdevices[i].DeviceData < u2fdevices[j].DeviceData
	})
	var totpdevices []registeredTOTPTDeviceDisplayInfo
	for i, deviceInfo := range profile.TOTPAuthData {
		deviceData := registeredTOTPTDeviceDisplayInfo{
			Enabled: deviceInfo.Enabled,
			Name:    deviceInfo.Name,
			Index:   i,
		}
		totpdevices = append(totpdevices, deviceData)
	}
	showTOTP := state.Config.Base.EnableLocalTOTP

	displayData := profilePageTemplateData{
		Username:             assumedUser,
		AuthUsername:         authData.Username,
		SessionExpires:       authData.expires(),
		Title:                "Keymaster User Profile",
		ShowU2F:              showU2F,
		JSSources:            JSSources,
		ReadOnlyMsg:          readOnlyMsg,
		UsersLink:            state.IsAdminUser(authData.Username),
		ShowExperimental:     state.IsAdminUser(authData.Username),
		RegisteredU2FToken:   u2fdevices,
		ShowTOTP:             showTOTP,
		RegisteredTOTPDevice: totpdevices,
	}
	if time.Until(profile.BootstrapOTP.ExpiresAt) > 0 &&
		len(profile.BootstrapOTP.Sha512Hash) >= 4 {
		displayData.BootstrapOTP = &bootstrapOtpTemplateData{
			ExpiresAt: profile.BootstrapOTP.ExpiresAt,
		}
		copy(displayData.BootstrapOTP.Fingerprint[:],
			profile.BootstrapOTP.Sha512Hash[:4])
	}
	logger.Debugf(1, "%v", displayData)

	err = state.htmlTemplate.ExecuteTemplate(w, "userProfilePage", displayData)
	if err != nil {
		logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

const u2fTokenManagementPath = "/api/v0/manageU2FToken"

// TODO: add duplicate action filter via cookies (for browser context).

func (state *RuntimeState) u2fTokenManagerHandler(w http.ResponseWriter, r *http.Request) {
	// User must be logged in
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	// TODO: ensure is a valid method (POST)
	err = r.ParseForm()
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		return
	}
	logger.Debugf(3, "Form: %+v", r.Form)

	assumedUser := r.Form.Get("username")

	// Have admin rights = Must be admin + authenticated with U2F
	hasAdminRights := state.IsAdminUserAndU2F(authData.Username,
		authData.AuthType)

	// Check params
	if !hasAdminRights && assumedUser != authData.Username {
		logger.Printf("bad username authUser=%s requested=%s", authData.Username, r.Form.Get("username"))
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}

	tokenIndex, err := strconv.ParseInt(r.Form.Get("index"), 10, 64)
	if err != nil {
		logger.Printf("tokenindex is not a number")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "tokenindex is not a number")
		return
	}

	//Do a redirect
	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
		return
	}

	// Todo: check for negative values
	_, ok := profile.U2fAuthData[tokenIndex]
	if !ok {
		logger.Debugf(1, "bad index number")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad index Value")
		return

	}

	actionName := r.Form.Get("action")
	switch actionName {
	case "Update":
		tokenName := r.Form.Get("name")
		if m, _ := regexp.MatchString("^[-/.a-zA-Z0-9_ ]+$", tokenName); !m {
			logger.Printf("%s", tokenName)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "invalidtokenName")
			return
		}
		profile.U2fAuthData[tokenIndex].Name = tokenName

	case "Disable":
		profile.U2fAuthData[tokenIndex].Enabled = false
	case "Enable":
		profile.U2fAuthData[tokenIndex].Enabled = true
	case "Delete":
		delete(profile.U2fAuthData, tokenIndex)
	default:
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Operation")
		return
	}

	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	// Success!
	returnAcceptType := getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		http.Redirect(w, r, profileURI(authData.Username, assumedUser), 302)
	default:
		w.WriteHeader(200)
		fmt.Fprintf(w, "Success!")
	}
	return
}

const clientConfHandlerPath = "/public/clientConfig"
const clientConfigText = `base:
    gen_cert_urls: "%s"
`

func (state *RuntimeState) serveClientConfHandler(w http.ResponseWriter, r *http.Request) {
	//w.WriteHeader(200)
	w.Header().Set("Content-Type", "text/yaml")
	fmt.Fprintf(w, clientConfigText, u2fAppID)
}

func (state *RuntimeState) defaultPathHandler(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if r.URL.Path == "/favicon.ico" {
		w.Header().Set("Cache-Control", "public, max-age=120")
		http.Redirect(w, r, "/static/favicon.ico", http.StatusFound)
		return
	}
	//redirect to profile
	if r.URL.Path[:] == "/" {
		//landing page
		if err := r.ParseForm(); err != nil {
			logger.Println(err)
			errCode := http.StatusInternalServerError
			errMessage := "Error parsing form"
			if strings.Contains(err.Error(), "invalid") {
				errCode = http.StatusBadRequest
				errMessage = "invalid query"
			}
			state.writeFailureResponse(w, r, errCode,
				errMessage)
			return
		}
		if r.Method == "GET" && len(r.Cookies()) < 1 {
			state.writeHTMLLoginPage(w, r, 200, getUserFromRequest(r),
				profilePath, "")
			return
		}

		http.Redirect(w, r, profilePath, 302)
		return
	}
	http.Error(w, "error not found", http.StatusNotFound)
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

	serviceMux := http.NewServeMux()
	serviceMux.HandleFunc(certgenPath, runtimeState.certGenHandler)
	serviceMux.HandleFunc(publicPath, runtimeState.publicPathHandler)
	serviceMux.HandleFunc(proto.LoginPath, runtimeState.loginHandler)
	serviceMux.HandleFunc(logoutPath, runtimeState.logoutHandler)
	serviceMux.HandleFunc(profilePath, runtimeState.profileHandler)
	serviceMux.HandleFunc(usersPath, runtimeState.usersHandler)
	serviceMux.HandleFunc(addUserPath, runtimeState.addUserHandler)
	serviceMux.HandleFunc(deleteUserPath, runtimeState.deleteUserHandler)
	//TODO: should enable only if bootraptop is enabled
	serviceMux.HandleFunc(generateBoostrapOTPPath,
		runtimeState.generateBootstrapOTP)

	serviceMux.HandleFunc(idpOpenIDCConfigurationDocumentPath,
		runtimeState.idpOpenIDCDiscoveryHandler)
	serviceMux.HandleFunc(idpOpenIDCJWKSPath,
		runtimeState.idpOpenIDCJWKSHandler)
	serviceMux.HandleFunc(idpOpenIDCAuthorizationPath,
		runtimeState.idpOpenIDCAuthorizationHandler)
	serviceMux.HandleFunc(idpOpenIDCTokenPath,
		runtimeState.idpOpenIDCTokenHandler)
	serviceMux.HandleFunc(idpOpenIDCUserinfoPath,
		runtimeState.idpOpenIDCUserinfoHandler)

	staticFilesPath :=
		filepath.Join(runtimeState.Config.Base.SharedDataDirectory,
			"static_files")
	serviceMux.Handle("/static/", cacheControlHandler(
		http.StripPrefix("/static/",
			http.FileServer(http.Dir(staticFilesPath)))))
	serviceMux.Handle("/static/compiled/", cacheControlHandler(
		http.StripPrefix("/static/compiled/", http.FileServer(AssetFile()))))
	customWebResourcesPath :=
		filepath.Join(runtimeState.Config.Base.SharedDataDirectory,
			"customization_data", "web_resources")
	if _, err = os.Stat(customWebResourcesPath); err == nil {
		serviceMux.Handle("/custom_static/", cacheControlHandler(
			http.StripPrefix("/custom_static/",
				http.FileServer(http.Dir(customWebResourcesPath)))))
	}
	serviceMux.HandleFunc(u2fRegustisterRequestPath,
		runtimeState.u2fRegisterRequest)
	serviceMux.HandleFunc(u2fRegisterRequesponsePath,
		runtimeState.u2fRegisterResponse)
	serviceMux.HandleFunc(u2fSignRequestPath, runtimeState.u2fSignRequest)
	serviceMux.HandleFunc(u2fSignResponsePath, runtimeState.u2fSignResponse)
	serviceMux.HandleFunc(webAutnRegististerRequestPath, runtimeState.webauthnBeginRegistration)
	serviceMux.HandleFunc(webAutnRegististerFinishPath, runtimeState.webauthnFinishRegistration)
	serviceMux.HandleFunc(webAuthnAuthBeginPath, runtimeState.webauthnAuthLogin)
	serviceMux.HandleFunc(webAuthnAuthFinishPath, runtimeState.webauthnAuthFinish)

	serviceMux.HandleFunc(vipAuthPath, runtimeState.VIPAuthHandler)
	serviceMux.HandleFunc(u2fTokenManagementPath,
		runtimeState.u2fTokenManagerHandler)
	serviceMux.HandleFunc(oauth2LoginBeginPath,
		runtimeState.oauth2DoRedirectoToProviderHandler)
	serviceMux.HandleFunc(redirectPath, runtimeState.oauth2RedirectPathHandler)
	serviceMux.HandleFunc(clientConfHandlerPath,
		runtimeState.serveClientConfHandler)
	serviceMux.HandleFunc(vipPushStartPath, runtimeState.vipPushStartHandler)
	serviceMux.HandleFunc(vipPollCheckPath, runtimeState.VIPPollCheckHandler)
	serviceMux.HandleFunc(totpGeneratNewPath, runtimeState.GenerateNewTOTP)
	serviceMux.HandleFunc(totpValidateNewPath, runtimeState.validateNewTOTP)
	serviceMux.HandleFunc(totpTokenManagementPath,
		runtimeState.totpTokenManagerHandler)
	serviceMux.HandleFunc(totpVerifyHandlerPath, runtimeState.verifyTOTPHandler)
	serviceMux.HandleFunc(totpAuthPath, runtimeState.TOTPAuthHandler)
	if runtimeState.Config.Okta.Domain != "" {
		serviceMux.HandleFunc(okta2FAauthPath, runtimeState.Okta2FAuthHandler)
		serviceMux.HandleFunc(oktaPushStartPath,
			runtimeState.oktaPushStartHandler)
		serviceMux.HandleFunc(oktaPollCheckPath,
			runtimeState.oktaPollCheckHandler)
	}
	if runtimeState.checkAwsRolesEnabled() {
		serviceMux.HandleFunc(paths.RequestAwsRoleCertificatePath,
			runtimeState.requestAwsRoleCertificateHandler)
	}
	// TODO(rgooch): Condition this on whether Bootstrap OTP is configured.
	//               The inline calls to getRequiredWebUIAuthLevel() should be
	//               moved to the config section and replaced with a simple
	//               bitfield test.
	serviceMux.HandleFunc(bootstrapOtpAuthPath,
		runtimeState.BootstrapOtpAuthHandler)
	if runtimeState.Config.Base.WebauthTokenForCliLifetime > 0 {
		serviceMux.HandleFunc(paths.SendAuthDocument,
			runtimeState.SendAuthDocumentHandler)
		serviceMux.HandleFunc(paths.ShowAuthToken,
			runtimeState.ShowAuthTokenHandler)
		serviceMux.HandleFunc(paths.VerifyAuthToken,
			runtimeState.VerifyAuthTokenHandler)
	}
	serviceMux.HandleFunc("/", runtimeState.defaultPathHandler)

	cfg := &tls.Config{
		ClientCAs:                runtimeState.ClientCAPool,
		ClientAuth:               tls.VerifyClientCertIfGiven,
		GetCertificate:           runtimeState.certManager.GetCertificate,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
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
	myCert, err := x509.ParseCertificate(runtimeState.caCertDer)
	if err != nil {
		panic(err)
	}
	runtimeState.ClientCAPool.AddCert(myCert)
	// Safari in MacOS 10.12.x required a cert to be presented by the user even
	// when optional.
	// Our usage shows this is less than 1% of users so we are now mandating
	// verification on issues we will need to update clientAuth back  to tls.RequestClientCert
	serviceTLSConfig := &tls.Config{
		ClientCAs:                runtimeState.ClientCAPool,
		ClientAuth:               tls.VerifyClientCertIfGiven,
		GetCertificate:           runtimeState.certManager.GetCertificate,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
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
