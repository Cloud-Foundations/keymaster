package ldap

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/authutil"
	"github.com/Cloud-Foundations/keymaster/lib/simplestorage"
)

const defaultCacheDuration = time.Hour * 96
const passwordDataType = 1
const browserResponseTimeoutSeconds = 7

func newAuthenticator(urllist []string, bindPattern []string,
	timeoutSecs uint, rootCAs *x509.CertPool,
	storage simplestorage.SimpleStore, logger log.DebugLogger) (
	*PasswordAuthenticator, error) {
	var authenticator PasswordAuthenticator
	for _, stringURL := range urllist {
		url, err := authutil.ParseLDAPURL(stringURL)
		if err != nil {
			return nil, err
		}
		authenticator.ldapURL = append(authenticator.ldapURL, url)
	}
	authenticator.bindPattern = bindPattern
	authenticator.timeoutSecs = timeoutSecs
	if timeoutSecs*uint(len(authenticator.ldapURL)) > uint(browserResponseTimeoutSeconds) {
		authenticator.timeoutSecs = uint(browserResponseTimeoutSeconds) / uint(len(authenticator.ldapURL))
	}
	authenticator.rootCAs = rootCAs
	authenticator.logger = logger
	authenticator.expirationDuration = defaultCacheDuration
	authenticator.storage = storage
	authenticator.cachedCredentials = make(map[string]cacheCredentialEntry)
	return &authenticator, nil
}

func convertToBindDN(username string, bind_pattern string) string {
	return fmt.Sprintf(bind_pattern, username)
}

func (pa *PasswordAuthenticator) updateOrDeletePasswordHash(valid bool, username string, password []byte) error {
	if pa.storage == nil {
		return errors.New("No db for updating password")
	}

	if valid {
		hash, err := authutil.Argon2MakeNewHash(password)
		if err != nil {
			if pa.logger != nil {
				pa.logger.Debugf(0, "Failure making new hash for password for user %s", username)
			}
			return nil
		}
		Expiration := time.Now().Add(pa.expirationDuration)
		err = pa.storage.UpsertSigned(username, passwordDataType, Expiration.Unix(), hash)
		if err != nil && pa.logger != nil {
			pa.logger.Debugf(0, "Failure inserting password into db for user %s", username)
		}
		return err

	} else {
		ok, hash, err := pa.storage.GetSigned(username, passwordDataType)
		if err != nil {
			return nil
		}
		if ok {
			err := authutil.Argon2CompareHashAndPassword(hash, password)
			if err == nil {
				pa.storage.DeleteSigned(username, passwordDataType)
			}
		}
	}
	return nil
}

func (pa *PasswordAuthenticator) passwordAuthenticate(username string,
	password []byte) (valid bool, err error) {
	valid = false
	for _, u := range pa.ldapURL {
		for _, bindPattern := range pa.bindPattern {
			bindDN := convertToBindDN(username, bindPattern)
			valid, err = authutil.CheckLDAPUserPassword(*u, bindDN, string(password), pa.timeoutSecs, pa.rootCAs)
			if err != nil {
				if pa.logger != nil {
					pa.logger.Debugf(1, "Error checking LDAP user password url= %s", u)
				}
				continue
			}
			err = pa.updateOrDeletePasswordHash(valid, username, password)
			if err != nil && pa.logger != nil {
				pa.logger.Debugf(0, "Updating local password hash for user %s", username)
			}
			return valid, nil

		}
	}
	if pa.storage != nil {
		if pa.logger != nil {
			pa.logger.Printf("Failed to check password against LDAP servers, using local hash db")
		}
		ok, hash, err := pa.storage.GetSigned(username, passwordDataType)
		if err != nil {
			return false, nil
		}
		if ok {
			err = authutil.Argon2CompareHashAndPassword(hash, password)
			if err == nil {
				return true, nil
			}
		}

	}

	return false, nil
}
