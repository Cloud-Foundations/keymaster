package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/authutil"
	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"golang.org/x/crypto/ssh"
)

const certgenPath = "/certgen/"

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
	authUser, authLevel, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)

	sufficientAuthLevel := false
	// We should do an intersection operation here
	for _, certPref := range state.Config.Base.AllowedAuthBackendsForCerts {
		if certPref == proto.AuthTypePassword {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeU2F && ((authLevel & AuthTypeU2F) == AuthTypeU2F) {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeSymantecVIP && ((authLevel & AuthTypeSymantecVIP) == AuthTypeSymantecVIP) {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeIPCertificate && ((authLevel & AuthTypeIPCertificate) == AuthTypeIPCertificate) {
			sufficientAuthLevel = true
		}
	}
	// if you have u2f you can always get the cert
	if (authLevel & AuthTypeU2F) == AuthTypeU2F {
		sufficientAuthLevel = true
	}

	if !sufficientAuthLevel {
		logger.Printf("Not enough auth level for getting certs")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Not enough auth level for getting certs")
		return
	}

	targetUser := r.URL.Path[len(certgenPath):]
	if authUser != targetUser {
		state.writeFailureResponse(w, r, http.StatusForbidden, "")
		logger.Printf("User %s asking for creds for %s", authUser, targetUser)
		return
	}
	logger.Debugf(3, "auth succedded for %s", authUser)

	switch r.Method {
	case "GET":
		logger.Debugf(3, "Got client GET connection")
		err = r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		logger.Debugf(3, "Got client POST connection")
		err = r.ParseMultipartForm(1e7)
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}

	duration := time.Duration(24 * time.Hour)
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

	certType := "ssh"
	if val, ok := r.Form["type"]; ok {
		certType = val[0]
	}
	logger.Printf("cert type =%s", certType)

	switch certType {
	case "ssh":
		state.postAuthSSHCertHandler(w, r, targetUser, keySigner, duration)
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

func (state *RuntimeState) postAuthSSHCertHandler(
	w http.ResponseWriter, r *http.Request, targetUser string,
	keySigner crypto.Signer, duration time.Duration) {
	signer, err := ssh.NewSignerFromSigner(keySigner)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer failed to load")
		return
	}

	var cert string
	var certBytes []byte
	switch r.Method {
	case "GET":
		cert, certBytes, err = certgen.GenSSHCertFileStringFromSSSDPublicKey(targetUser, signer, state.HostIdentity, duration)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	case "POST":
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
		//validKey, err := regexp.MatchString("^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) [a-zA-Z0-9/+]+=?=? .*$", userPubKey)
		validKey, err := regexp.MatchString("^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) [a-zA-Z0-9/+]+=?=? ?.{0,512}\n?$", userPubKey)
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		if !validKey {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid File, bad re")
			logger.Printf("invalid file, bad re")
			return

		}

		cert, certBytes, err = certgen.GenSSHCertFileString(targetUser, userPubKey, signer, state.HostIdentity, duration)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			logger.Printf("signUserPubkey Err")
			return
		}

	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return

	}
	eventNotifier.PublishSSH(certBytes)
	metricLogCertDuration("ssh", "granted", float64(duration.Seconds()))

	w.Header().Set("Content-Disposition", `attachment; filename="id_rsa-cert.pub"`)
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", cert)
	logger.Printf("Generated SSH Certifcate for %s", targetUser)
	go func(username string, certType string) {
		metricsMutex.Lock()
		defer metricsMutex.Unlock()
		certGenCounter.WithLabelValues(username, certType).Inc()
	}(targetUser, "ssh")
}

func (state *RuntimeState) getUserGroups(username string) ([]string, error) {
	if state.gitDB != nil {
		groups, err := state.gitDB.GetUserGroups(username, nil)
		if err != nil {
			return nil, err
		}
		return prependGroups(groups, state.Config.UserInfo.GitDB.GroupPrepend),
			nil
	}
	ldapConfig := state.Config.UserInfo.Ldap
	var timeoutSecs uint
	timeoutSecs = 2
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
		return prependGroups(groups, ldapConfig.GroupPrepend), nil

	}
	if ldapConfig.LDAPTargetURLs == "" {
		var emptyGroup []string
		return emptyGroup, nil
	}
	err := errors.New("error getting the groups")
	return nil, err
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
			logger.Println(err)
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
	var cert string
	switch r.Method {
	case "POST":
		file, _, err := r.FormFile("pubkeyfile")
		if err != nil {
			logger.Println(err)
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
			logger.Printf("Cannot parse public key")
			return
		}
		caCert, err := x509.ParseCertificate(state.caCertDer)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			logger.Printf("Cannot parse CA Der data")
			return
		}
		derCert, err := certgen.GenUserX509Cert(targetUser, userPub, caCert,
			keySigner, state.KerberosRealm, duration, groups, organizations)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			logger.Printf("Cannot Generate x509cert")
			return
		}
		eventNotifier.PublishX509(derCert)
		cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
			Bytes: derCert}))

	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return

	}
	metricLogCertDuration("x509", "granted", float64(duration.Seconds()))

	w.Header().Set("Content-Disposition", `attachment; filename="userCert.pem"`)
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", cert)
	logger.Printf("Generated x509 Certifcate for %s", targetUser)
	go func(username string, certType string) {
		metricsMutex.Lock()
		defer metricsMutex.Unlock()
		certGenCounter.WithLabelValues(username, certType).Inc()
	}(targetUser, "x509")
}
