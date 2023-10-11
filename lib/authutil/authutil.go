package authutil

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/cviecco/argon2"
	"github.com/foomo/htpasswd"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/ldap.v2"
)

// The argon2 defaults are:
// t = 3
// m = 12  // memory usage 2^N
// p = 1
// l = 32
// We will use slightly bigger values:

const argon2t = 40
const argon2m = 20
const argon2p = 2
const argon2l = 32

//There is no well defined number for argon2. We define our own
const argon2dPrefix = "$argon2d$"

const randomStringEntropyBytes = 32

func genRandomString() (string, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rb), nil
}

// The format of the hash will be:
// $99d$SALT:HEXVALUE

func Argon2MakeNewHash(password []byte) (string, error) {

	salt, err := genRandomString()
	if err != nil {
		return "", err
	}
	key, err := argon2.Key(password, []byte(salt), argon2t, argon2p, argon2m, argon2l)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s:%x", argon2dPrefix, salt, key), nil

}

// We only support argon2d as is the only pure golang implementation
func Argon2CompareHashAndPassword(hash string, password []byte) error {
	if !strings.HasPrefix(hash, argon2dPrefix) {
		err := errors.New("Dont understand hash format")
		return err
	}
	splitHashString := strings.SplitN(hash, ":", 2)
	hexKey := splitHashString[1]
	salt := splitHashString[0][len(argon2dPrefix):]
	//log.Printf("salt='%s' heykey=%s", salt, hexKey)
	key, err := argon2.Key(password, []byte(salt), argon2t, argon2p, argon2m, argon2l)
	if err != nil {
		return err
	}
	if hexKey == fmt.Sprintf("%x", key) {
		return nil
	}
	return errors.New("invalid password")
	//return nil
}

func CheckHtpasswdUserPassword(username string, password string, htpasswdBytes []byte) (bool, error) {
	//	secrets := HtdigestFileProvider(htpasswdFilename)
	passwords, err := htpasswd.ParseHtpasswd(htpasswdBytes)
	if err != nil {
		return false, err
	}
	hash, ok := passwords[username]
	if !ok {
		return false, nil
	}
	// only understand bcrypt
	if !strings.HasPrefix(hash, "$2y$") {
		err := errors.New("Can only use bcrypt for htpasswd")
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false, nil
	}
	return true, nil

}

func getLDAPConnection(u url.URL, timeoutSecs uint, rootCAs *x509.CertPool) (*ldap.Conn, string, error) {
	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldap scheme (we only support ldaps")
		return nil, "", err
	}
	//hostnamePort := server + ":636"
	serverPort := strings.Split(u.Host, ":")
	port := "636"
	if len(serverPort) == 2 {
		port = serverPort[1]
	}
	server := serverPort[0]
	hostnamePort := server + ":" + port

	timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	start := time.Now()
	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", hostnamePort,
		&tls.Config{ServerName: server, RootCAs: rootCAs, MinVersion: tls.VersionTLS12})
	if err != nil {
		errorTime := time.Since(start).Seconds() * 1000
		log.Printf("connction failure for:%s (%s)(time(ms)=%v)", server, err.Error(), errorTime)
		return nil, "", err
	}

	// we dont close the tls connection directly  close defer to the new ldap connection
	conn := ldap.NewConn(tlsConn, true)
	return conn, server, nil
}

func CheckLDAPConnection(u url.URL, timeoutSecs uint, rootCAs *x509.CertPool) error {
	conn, _, err := getLDAPConnection(u, timeoutSecs, rootCAs)
	if err != nil {
		return err
	}
	defer conn.Close()
	timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	conn.SetTimeout(timeout)
	conn.Start()
	return nil
}

func CheckLDAPUserPassword(u url.URL, bindDN string, bindPassword string, timeoutSecs uint, rootCAs *x509.CertPool) (bool, error) {
	timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	conn, server, err := getLDAPConnection(u, timeoutSecs, rootCAs)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	//connectionTime := time.Since(start).Seconds() * 1000

	conn.SetTimeout(timeout)
	conn.Start()
	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		log.Printf("Bind failure for server:%s bindDN:'%s' (%s)", server, bindDN, err.Error())
		if strings.Contains(err.Error(), "Invalid Credentials") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func ParseLDAPURL(ldapUrl string) (*url.URL, error) {
	u, err := url.Parse(ldapUrl)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldap scheme (we only support ldaps")
		return nil, err
	}
	//extract port if any... and if NIL then set it to 636
	return u, nil
}

func getUserDNAndSimpleGroups(conn *ldap.Conn, UserSearchBaseDNs []string, UserSearchFilter string, username string) (string, []string, error) {
	for _, searchDN := range UserSearchBaseDNs {
		searchRequest := ldap.NewSearchRequest(
			searchDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			//fmt.Sprintf("(&(objectClass=organizationalPerson)&(uid=%s))", username),
			fmt.Sprintf(UserSearchFilter, username),
			[]string{"dn", "memberOf"},
			nil,
		)
		sr, err := conn.Search(searchRequest)
		if err != nil {
			return "", nil, err
		}
		if len(sr.Entries) != 1 {
			log.Printf("User does not exist or too many entries returned")
			continue
		}
		userDN := sr.Entries[0].DN
		userGroups := sr.Entries[0].GetAttributeValues("memberOf")
		return userDN, userGroups, nil
	}
	return "", nil, nil
}

func getSimpleUserAttributes(conn *ldap.Conn, UserSearchBaseDNs []string,
	UserSearchFilter string, username string, attributes []string) (m map[string][]string, err error) {
	for _, searchDN := range UserSearchBaseDNs {
		searchRequest := ldap.NewSearchRequest(
			searchDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			//fmt.Sprintf("(&(objectClass=organizationalPerson)&(uid=%s))", username),
			fmt.Sprintf(UserSearchFilter, username),
			attributes,
			nil,
		)
		sr, err := conn.Search(searchRequest)
		if err != nil {
			return nil, err
		}
		if len(sr.Entries) != 1 {
			log.Printf("User does not exist or too many entries returned")
			continue
		}
		m = make(map[string][]string)
		for _, attr := range attributes {
			m[attr] = sr.Entries[0].GetAttributeValues(attr)
		}
		return m, nil
	}
	err = errors.New("user not found or too many users found")
	return nil, err
}

func extractCNFromDNString(input []string) (output []string, err error) {
	re := regexp.MustCompile("^cn=([^,]+),.*")
	for _, dn := range input {
		matches := re.FindStringSubmatch(dn)
		if len(matches) == 2 {
			output = append(output, matches[1])
		} else {
			log.Printf("dn='%s' matches=%v", dn, matches)
			output = append(output, dn)
		}
	}
	return output, nil
}

func getUserGroupsRFC2307bis(conn *ldap.Conn, UserSearchBaseDNs []string,
	UserSearchFilter string, username string) ([]string, error) {
	dn, groupDNs, err := getUserDNAndSimpleGroups(conn, UserSearchBaseDNs, UserSearchFilter, username)
	if err != nil {
		return nil, err
	}
	if dn == "" {
		return nil, errors.New("User does not exist or too many entries returned")
	}
	groupCNs, err := extractCNFromDNString(groupDNs)
	if err != nil {
		return nil, err
	}
	return groupCNs, nil
}

func getUserGroupsRFC2307(conn *ldap.Conn, GroupSearchBaseDNs []string,
	groupSearchFilter string, username string) (userGroups []string, err error) {
	for _, searchDN := range GroupSearchBaseDNs {
		searchRequest := ldap.NewSearchRequest(
			searchDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf(groupSearchFilter, username),
			[]string{"cn"},
			nil,
		)
		sr, err := conn.Search(searchRequest)
		if err != nil {
			log.Printf("error on search request err:%s", err)
			return nil, err
		}
		for _, entry := range sr.Entries {
			userGroups = append(userGroups, entry.GetAttributeValues("cn")...)
		}
	}
	return userGroups, nil
}

func GetLDAPUserGroups(u url.URL, bindDN string, bindPassword string,
	timeoutSecs uint, rootCAs *x509.CertPool,
	username string,
	UserSearchBaseDNs []string, UserSearchFilter string,
	GroupSearchBaseDNs []string, GroupSearchFilter string) ([]string, error) {
	timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	conn, _, err := getLDAPConnection(u, timeoutSecs, rootCAs)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetTimeout(timeout)
	conn.Start()
	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		return nil, err
	}
	rfcGroups, err := getUserGroupsRFC2307(conn, GroupSearchBaseDNs, GroupSearchFilter, username)
	if err != nil {
		return nil, err
	}
	memberGroups, err := getUserGroupsRFC2307bis(conn, UserSearchBaseDNs, UserSearchFilter, username)
	if err != nil {
		return nil, err
	}
	groupMap := make(map[string]struct{})
	for _, group := range rfcGroups {
		groupMap[group] = struct{}{}
	}
	for _, group := range memberGroups {
		groupMap[group] = struct{}{}
	}
	var userGroups []string
	for group := range groupMap {
		userGroups = append(userGroups, group)
	}
	return userGroups, nil
}

func GetLDAPUserAttributes(u url.URL, bindDN string, bindPassword string,
	timeoutSecs uint, rootCAs *x509.CertPool,
	username string,
	UserSearchBaseDNs []string, UserSearchFilter string,
	attributes []string) (map[string][]string, error) {

	timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	conn, _, err := getLDAPConnection(u, timeoutSecs, rootCAs)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetTimeout(timeout)
	conn.Start()
	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		return nil, err
	}

	return getSimpleUserAttributes(conn, UserSearchBaseDNs,
		UserSearchFilter, username, attributes)
}
