package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/authutil"
	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/util"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"golang.org/x/crypto/ssh"
)

const (
	certgenPath            = "/certgen/"
	maxCertificateLifetime = time.Hour * 24
)

func prependGroups(groups []string, prefix string) []string {
	if prefix == "" {
		return groups
	}
	newGroups := make([]string, 0, len(groups))
	for _, group := range groups {
		newGroups = append(newGroups, prefix+group)
	}
	return newGroups
}

func (state *RuntimeState) certGenHandler(w http.ResponseWriter, r *http.Request) {
	var signerIsNull bool
	var keySigner crypto.Signer

	// copy runtime singer if not nil
	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	if !signerIsNull {
		keySigner = state.Signer
	}
	state.Mutex.Unlock()

	//local sanity tests
	if signerIsNull {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer not loaded")
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authData, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	logger.Debugf(1,
		"Certgen, authenticated at level=%x, username=`%s`, expires=%s",
		authData.AuthType, authData.Username, authData.ExpiresAt)

	sufficientAuthLevel := false
	// We should do an intersection operation here
	for _, certPref := range state.Config.Base.AllowedAuthBackendsForCerts {
		if certPref == proto.AuthTypePassword {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeU2F &&
			((authData.AuthType & AuthTypeU2F) == AuthTypeU2F) {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeTOTP &&
			((authData.AuthType & AuthTypeTOTP) == AuthTypeTOTP) {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeSymantecVIP &&
			((authData.AuthType & AuthTypeSymantecVIP) == AuthTypeSymantecVIP) {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeIPCertificate &&
			((authData.AuthType & AuthTypeIPCertificate) == AuthTypeIPCertificate) {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeOkta2FA &&
			((authData.AuthType & AuthTypeOkta2FA) == AuthTypeOkta2FA) {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeWebauthForCLI &&
			((authData.AuthType & AuthTypeWebauthForCLI) ==
				AuthTypeWebauthForCLI) {
			sufficientAuthLevel = true
		}
	}
	// if you have u2f you can always get the cert
	if (authData.AuthType & AuthTypeU2F) == AuthTypeU2F {
		sufficientAuthLevel = true
	}

	if !sufficientAuthLevel {
		logger.Printf("Not enough auth level for getting certs")
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"Not enough auth level for getting certs")
		return
	}

	targetUser := r.URL.Path[len(certgenPath):]
	if authData.Username != targetUser {
		state.writeFailureResponse(w, r, http.StatusForbidden, "")
		logger.Printf("User %s asking for creds for %s",
			authData.Username, targetUser)
		return
	}
	targetUser = authData.Username
	logger.Debugf(3, "auth succedded for %s", authData.Username)

	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}

	logger.Debugf(3, "Got client POST connection")
	err = r.ParseMultipartForm(1e7)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		return
	}
	duration := maxCertificateLifetime
	if formDuration, ok := r.Form["duration"]; ok {
		stringDuration := formDuration[0]
		newDuration, err := time.ParseDuration(stringDuration)
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form (duration)")
			return
		}
		metricLogCertDuration("unparsed", "requested", float64(newDuration.Seconds()))
		if newDuration > duration {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form (invalid duration)")
			return
		}
		duration = newDuration
	}
	maxDuration := time.Until(authData.IssuedAt.Add(maxCertificateLifetime))
	if duration > maxDuration {
		duration = maxDuration
	}

	certType := "ssh"
	if val, ok := r.Form["type"]; ok {
		certType = val[0]
	}
	logger.Debugf(1, "cert type =%s", certType)

	switch certType {
	case "ssh":
		state.postAuthSSHCertHandler(w, r, targetUser, duration)
		return
	case "x509":
		state.postAuthX509CertHandler(w, r, targetUser, keySigner, duration, false)
		return
	case "x509-kubernetes":
		state.postAuthX509CertHandler(w, r, targetUser, keySigner, duration, true)
		return
	default:
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Unrecognized cert type")
		return
	}
}

// returns 3 values, if the key is valid, if the key is not valid, the text reason why and and error if it was an internal error
func getValidSSHPublicKey(userPubKey string) (ssh.PublicKey, error, error) {
	validKey, err := regexp.MatchString("^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) [a-zA-Z0-9/+]+=?=? ?.{0,512}\n?$", userPubKey)
	if err != nil {
		return nil, nil, err
	}
	if !validKey {
		return nil, fmt.Errorf("Invalid File, bad re"), nil
	}
	userSSH, _, _, _, err := ssh.ParseAuthorizedKey([]byte(userPubKey))
	if err != nil {
		return nil, fmt.Errorf("invalid file, unparseable"), nil
	}
	// The next check should never fail, as all of our supported keys are ssh.CryptoPublicKey's but
	// to prevent potential future panics we check anyway
	cryptoPubKey, ok := userSSH.(ssh.CryptoPublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("Cannot transform ssh key into crypto key, inbound=%s", userPubKey)
	}
	validKey, err = certgen.ValidatePublicKeyStrength(cryptoPubKey.CryptoPublicKey())
	if err != nil {
		return nil, nil, err
	}
	if !validKey {
		return nil, fmt.Errorf("Invalid File, Check Key strength/key type"), nil
	}
	return userSSH, nil, nil
}

func (state *RuntimeState) expandSSHExtensions(username string) (map[string]string, error) {
	mapper := func(placeholderName string) string {
		switch placeholderName {
		case "USERNAME":
			return username
		}
		return ""
	}
	userExtensions := make(map[string]string)
	for _, extension := range state.Config.Base.SSHCertConfig.Extensions {
		key := os.Expand(extension.Key, mapper)
		value := os.Expand(extension.Value, mapper)
		userExtensions[key] = value
	}

	return userExtensions, nil
}

func (state *RuntimeState) postAuthSSHCertHandler(
	w http.ResponseWriter, r *http.Request, targetUser string,
	duration time.Duration) {

	var certString string
	var cert ssh.Certificate
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}

	file, _, err := r.FormFile("pubkeyfile")
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Missing public key file")
		return
	}
	defer file.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(file)
	userPubKey := buf.String()

	sshUserPublicKey, userErr, err := getValidSSHPublicKey(userPubKey)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if userErr != nil {
		logger.Printf("validating Error err: %s", userErr)
		state.writeFailureResponse(w, r, http.StatusBadRequest, userErr.Error())
		return
	}
	var cryptoSigner crypto.Signer
	switch sshUserPublicKey.Type() {
	case ssh.KeyAlgoED25519:
		if state.Ed25519Signer == nil {
			logger.Printf("requesting an Ed25519 cert, but no such ca defined")
			state.writeFailureResponse(w, r, http.StatusUnprocessableEntity, "key type not allowed")
			return
		}
		cryptoSigner = state.Ed25519Signer
	default:
		cryptoSigner = state.Signer
	}
	signer, err := ssh.NewSignerFromSigner(cryptoSigner)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer failed to load")
		return
	}
	extensions, err := state.expandSSHExtensions(targetUser)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Extensions Failed to expand")
		return
	}
	certString, cert, err = certgen.GenSSHCertFileString(targetUser, userPubKey, signer, state.HostIdentity, duration, extensions)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("signUserPubkey Err")
		return
	}

	eventNotifier.PublishSSH(cert.Marshal())
	metricLogCertDuration("ssh", "granted", float64(duration.Seconds()))
	clientIpAddress := util.GetRequestRealIp(r)

	w.Header().Set("Content-Disposition", "attachment; filename=\""+cert.Type()+"-cert.pub\"")
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", certString)
	logger.Printf("Generated SSH Certificate for %s (from %s) . Serial: %d",
		targetUser, clientIpAddress, cert.Serial)
	go func(username string, certType string) {
		metricsMutex.Lock()
		defer metricsMutex.Unlock()
		certGenCounter.WithLabelValues(username, certType).Inc()
	}(targetUser, "ssh")
}

func (state *RuntimeState) getGitDbUserGroups(username string) (
	bool, []string, error) {
	if state.gitDB == nil {
		return false, nil, nil
	}
	groups, err := state.gitDB.GetUserGroups(username)
	if err != nil {
		return true, nil, err
	}
	return true,
		prependGroups(groups, state.Config.UserInfo.GitDB.GroupPrepend),
		nil
}

func (state *RuntimeState) getLdapUserGroups(username string) (
	bool, []string, error) {
	ldapConfig := state.Config.UserInfo.Ldap
	var timeoutSecs uint
	timeoutSecs = 2
	if ldapConfig.LDAPTargetURLs == "" {
		return false, nil, nil
	}
	for _, ldapUrl := range strings.Split(ldapConfig.LDAPTargetURLs, ",") {
		if len(ldapUrl) < 1 {
			continue
		}
		u, err := authutil.ParseLDAPURL(ldapUrl)
		if err != nil {
			logger.Printf("Failed to parse ldapurl '%s'", ldapUrl)
			continue
		}
		groups, err := authutil.GetLDAPUserGroups(*u,
			ldapConfig.BindUsername, ldapConfig.BindPassword,
			timeoutSecs, nil, username,
			ldapConfig.UserSearchBaseDNs, ldapConfig.UserSearchFilter,
			ldapConfig.GroupSearchBaseDNs, ldapConfig.GroupSearchFilter)
		if err != nil {
			continue
		}
		return true, prependGroups(groups, ldapConfig.GroupPrepend), nil

	}
	return true, nil, errors.New("error getting the groups")
}

func (state *RuntimeState) getUserGroups(username string) ([]string, error) {
	if config, groups, err := state.getLdapUserGroups(username); config {
		return groups, err
	}
	if config, groups, err := state.getGitDbUserGroups(username); config {
		return groups, err
	}
	return nil, nil
}

func (state *RuntimeState) getServiceMethods(username string) (
	[]string, error) {
	if state.gitDB == nil {
		return nil, nil
	}
	return state.gitDB.GetUserServiceMethods(username)
}

func (state *RuntimeState) postAuthX509CertHandler(
	w http.ResponseWriter, r *http.Request, targetUser string,
	keySigner crypto.Signer, duration time.Duration,
	kubernetesHack bool) {

	var userGroups, groups []string
	// Getting user groups can be a failure, in this case we dont want to
	// abort if we are not explicitly asking for groups in our cert.
	if kubernetesHack || r.Form.Get("addGroups") == "true" {
		var err error
		logger.Debugf(2, "Groups needed for cert")
		userGroups, err = state.getUserGroups(targetUser)
		if err != nil {
			logger.Printf("Cannot get user groups: %s\n", err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
	}
	if r.Form.Get("addGroups") == "true" {
		groups = userGroups
	}
	organizations := []string{"keymaster"}
	if kubernetesHack {
		organizations = userGroups
	}
	serviceMethods, err := state.getServiceMethods(targetUser)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	var cert string
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}

	file, _, err := r.FormFile("pubkeyfile")
	if err != nil {
		logger.Printf("Cannot get public key from form: %s\n", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Missing public key file")
		return
	}
	defer file.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(file)

	block, _ := pem.Decode(buf.Bytes())
	if block == nil || block.Type != "PUBLIC KEY" {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Invalid File, Unable to decode pem")
		logger.Printf("invalid file, unable to decode pem")
		return
	}
	userPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Cannot parse public key")
		logger.Printf("Cannot parse public key: %s\n", err)
		return
	}
	validKey, err := certgen.ValidatePublicKeyStrength(userPub)
	if err != nil {
		logger.Printf("Cannot validate public key strength: %s\n", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if !validKey {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid File, Check Key strength/key type")
		logger.Printf("Invalid File, Check Key strength/key type")
		return
	}
	caCert, err := x509.ParseCertificate(state.caCertDer)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Cannot parse CA Der: %s\n data", err)
		return
	}
	derCert, err := certgen.GenUserX509Cert(targetUser, userPub, caCert,
		keySigner, state.KerberosRealm, duration, groups, organizations,
		serviceMethods)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Cannot Generate x509cert: %s\n", err)
		return
	}
	parsedCert, err := x509.ParseCertificate(derCert)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Cannot Parse Generated x509cert: %s\n", err)
		return
	}

	eventNotifier.PublishX509(derCert)
	cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: derCert}))

	metricLogCertDuration("x509", "granted", float64(duration.Seconds()))

	clientIpAddress := util.GetRequestRealIp(r)

	w.Header().Set("Content-Disposition", `attachment; filename="userCert.pem"`)
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", cert)
	logger.Printf("Generated x509 Certificate for %s (from %s). Serial: %s",
		targetUser, clientIpAddress, parsedCert.SerialNumber.String())
	go func(username string, certType string) {
		metricsMutex.Lock()
		defer metricsMutex.Unlock()
		certGenCounter.WithLabelValues(username, certType).Inc()
	}(targetUser, "x509")
}
