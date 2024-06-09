/*
Package certgen contains a set of utilities used to generate ssh certificates.
*/
package certgen

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"golang.org/x/crypto/ssh"
)

const (
	extensionSoftLimit = 10 << 10 // 10 KiB
	extensionHardLimit = 12 << 10 // 12 KiB
)

// addExtraExtension will add an extra extension to a certificate template
// provided the size limit is not exceeded.
func addExtraExtension(template *x509.Certificate, extension *pkix.Extension,
	name string, logger log.DebugLogger) {
	if extension == nil {
		return
	}
	totalExtensionSize := len(extension.Value)
	for _, existingExtension := range template.ExtraExtensions {
		totalExtensionSize += len(existingExtension.Value)
	}
	if totalExtensionSize > extensionHardLimit {
		logger.Printf("%s extension for %s too large (%d), ignoring\n",
			name, template.Subject.CommonName, name, totalExtensionSize)
		return
	}
	if totalExtensionSize > extensionSoftLimit {
		logger.Printf("warning: %s extension for %s is large: %d\n",
			name, template.Subject.CommonName, name, totalExtensionSize)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, *extension)
}

// GetUserPubKeyFromSSSD user authorized keys content based on the running sssd configuration
func GetUserPubKeyFromSSSD(username string) (string, error) {
	cmd := exec.Command("/usr/bin/sss_ssh_authorizedkeys", username)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

func goCertToFileString(c ssh.Certificate, username string) (string, error) {
	certBytes := c.Marshal()
	encoded := base64.StdEncoding.EncodeToString(certBytes)
	fileComment := "/tmp/" + username + "-" + c.SignatureKey.Type() + "-cert.pub"
	return c.Type() + " " + encoded + " " + fileComment, nil
}

// gen_user_cert a username and key, returns a short lived cert for that user
func GenSSHCertFileString(username string, userPubKey string, signer ssh.Signer, host_identity string, duration time.Duration, customExtensions map[string]string) (certString string, cert ssh.Certificate, err error) {
	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(userPubKey))
	if err != nil {
		return "", cert, err
	}
	keyIdentity := host_identity + "_" + username

	currentEpoch := uint64(time.Now().Unix())
	expireEpoch := currentEpoch + uint64(duration.Seconds())

	nBig, err := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFF))
	if err != nil {
		return "", cert, err
	}
	serial := (currentEpoch << 32) | nBig.Uint64()
	// Here we add standard extensions
	extensions := map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}
	if customExtensions != nil {
		for key, value := range customExtensions {
			//safeguard for invalid definition
			if key == "" {
				continue
			}
			extensions[key] = value
		}
	}
	// The values of the permissions are taken from the default values used
	// by ssh-keygen
	cert = ssh.Certificate{
		Key:             userKey,
		CertType:        ssh.UserCert,
		SignatureKey:    signer.PublicKey(),
		ValidPrincipals: []string{username},
		KeyId:           keyIdentity,
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
		Serial:          serial,
		Permissions:     ssh.Permissions{Extensions: extensions},
	}

	err = cert.SignCert(bytes.NewReader(cert.Marshal()), signer)
	if err != nil {
		return "", cert, err
	}
	certString, err = goCertToFileString(cert, username)
	if err != nil {
		return "", cert, err
	}
	return certString, cert, nil
}

func GenSSHCertFileStringFromSSSDPublicKey(userName string, signer ssh.Signer, hostIdentity string, duration time.Duration) (certString string, cert ssh.Certificate, err error) {

	userPubKey, err := GetUserPubKeyFromSSSD(userName)
	if err != nil {
		return "", cert, err
	}
	return GenSSHCertFileString(userName, userPubKey, signer, hostIdentity, duration, nil)
}

// X509 section
func getPubKeyFromPem(pubkey string) (pub interface{}, err error) {
	block, rest := pem.Decode([]byte(pubkey))
	if block == nil || block.Type != "PUBLIC KEY" {
		err := fmt.Errorf("Cannot decode user public Key '%s' rest='%s'", pubkey, string(rest))
		if block != nil {
			err = fmt.Errorf("public key bad type %s", block.Type)
		}
		return nil, err
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func GetSignerFromPEMBytes(privateKey []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		err := errors.New("Cannot decode Private Key")
		return nil, err
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsedIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch v := parsedIface.(type) {
		case *rsa.PrivateKey:
			return v, nil
		case *ecdsa.PrivateKey:
			return v, nil
		case ed25519.PrivateKey:
			return v, nil
		default:
			return nil, fmt.Errorf("Type not recognized  %T!\n", v)
		}
	case "OPENSSH PRIVATE KEY":
		parsedIface, err := ssh.ParseRawPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		switch v := parsedIface.(type) {
		case *rsa.PrivateKey:
			return v, nil
		case *ecdsa.PrivateKey:
			return v, nil
		case *ed25519.PrivateKey:
			return v, nil
		default:
			return nil, fmt.Errorf("Type not recognized  %T!\n", v)
		}
	default:
		err := errors.New("Cannot process that key")
		return nil, err
	}
}

// ValidatePublicKeyStrenght checks if the "strength" of the key is good enough to be considered secure
// At this moment it checks for sizes of parameters only. For RSA it means bits>=2041 && exponent>=65537,
// For EC curves it means bitsize>=256. ec25519 is considered secure. All other public keys are not
// considered secure.
func ValidatePublicKeyStrength(pub interface{}) (bool, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.Size() < 256 { //ksize is in bytes
			return false, nil
		}

		if k.E < 65537 {
			return false, nil
		}
		return true, nil
	case *ecdsa.PublicKey:
		// TODO: check for the actual curves used
		if k.Curve.Params().BitSize < 255 {
			return false, nil
		}
		return true, nil
	case *ed25519.PublicKey, ed25519.PublicKey:
		return true, nil
	default:
		return false, nil
	}
}

/*
func derBytesCertToCertAndPem(derBytes []byte) (*x509.Certificate, string, error) {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, "", err
	}
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	return cert, pemCert, nil
}
*/

// On the initial version of keymaster we used the base64 encoding
// of the sha256sum of the rsa signature of the sha256 of the
// common name. This to have a stable, key dependent
// serial number.
// However this was a bad idea as:
// 1. Not all signers can use sha256
// 2. Not all signatures are stable.
//
// Thus we will keep the rsa behaviour for compatiblity reasons
// But for all other keys we will just return the pkix asn1 encoding
// of the public key
func getKMCompatbileKeyStableBytesForSerial(priv interface{}, commonName []byte) ([]byte, error) {
	switch v := priv.(type) {
	case *rsa.PrivateKey:
		sum := sha256.Sum256(commonName)
		return v.Sign(rand.Reader, sum[:], crypto.SHA256)
	case *ecdsa.PrivateKey:
		return x509.MarshalPKIXPublicKey(v.Public())
	case ed25519.PrivateKey:
		return x509.MarshalPKIXPublicKey(v.Public())
	default:
		return nil, fmt.Errorf("Type not recognized  %T!\n", v)
	}
}

// return both an internal representation an the pem representation of the string
// As long as the issuer value matches THEN the serial number can be different every time
func GenSelfSignedCACert(commonName string, organization string, caPriv crypto.Signer) ([]byte, error) {
	//// Now do the actual work...
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * 365 * 8 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	keyStableBytes, err := getKMCompatbileKeyStableBytesForSerial(caPriv, []byte(commonName))
	if err != nil {
		return nil, err
	}
	sigSum := sha256.Sum256(keyStableBytes)
	sig := base64.StdEncoding.EncodeToString(sigSum[:])
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
			SerialNumber: sig,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		//ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, caPriv.Public(), caPriv)
}

// From RFC 4120 section 5.2.2 (https://tools.ietf.org/html/rfc4120)
type KerberosPrincipal struct {
	Len       int      `asn1:"explicit,tag:0"`
	Principal []string `asn1:"explicit,tag:1"`
}

// From RFC 4556 section 3.2.2 (https://tools.ietf.org/html/rfc4556.html)
type KRB5PrincipalName struct {
	Realm     string            `asn1:"explicit,tag:0"`
	Principal KerberosPrincipal `asn1:"explicit,tag:1"`
}

type PKInitSANAnotherName struct {
	Id    asn1.ObjectIdentifier
	Value KRB5PrincipalName `asn1:"explicit,tag:0"`
}

// Since currently asn1 cannot mashal into GeneralString (https://github.com/golang/go/issues/18832)
// We make this hack since we know the positions of the items we want to change
func changePrintableStringToGeneralString(kerberosRealm string, inString []byte) []byte {
	position := 16
	inString[position] = 27

	position = position + 1 + len(kerberosRealm) + 14
	inString[position] = 27

	return inString
}

func genSANExtension(userName string, kerberosRealm *string) (*pkix.Extension, error) {
	if kerberosRealm == nil {
		return nil, nil
	}
	krbRealm := *kerberosRealm

	//1.3.6.1.5.2.2
	krbSanAnotherName := PKInitSANAnotherName{
		Id: []int{1, 3, 6, 1, 5, 2, 2},
		Value: KRB5PrincipalName{
			Realm:     krbRealm,
			Principal: KerberosPrincipal{Len: 1, Principal: []string{userName}},
		},
	}
	krbSanAnotherNameDer, err := asn1.Marshal(krbSanAnotherName)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("ext: %+x\n", krbSanAnotherNameDer)
	krbSanAnotherNameDer = changePrintableStringToGeneralString(krbRealm, krbSanAnotherNameDer)
	krbSanAnotherNameDer[0] = 0xA0
	//fmt.Printf("ext: %+x\n", krbSanAnotherNameDer)

	// inspired by marshalSANs in x509.go
	var rawValues []asn1.RawValue
	rawValues = append(rawValues, asn1.RawValue{FullBytes: krbSanAnotherNameDer})

	rawSan, err := asn1.Marshal(rawValues)
	if err != nil {
		return nil, err
	}

	sanExtension := pkix.Extension{
		Id:    []int{2, 5, 29, 17},
		Value: rawSan,
	}

	return &sanExtension, nil
}

func makeGroupListExtension(groups []string) (*pkix.Extension, error) {
	if len(groups) < 1 {
		return nil, nil
	}
	encodedValue, err := asn1.Marshal(groups)
	if err != nil {
		return nil, err
	}
	groupListExtension := pkix.Extension{
		// See github.com/Cloud-Foundations/Dominator/lib/constants.GroupListOID
		Id:    []int{1, 3, 6, 1, 4, 1, 9586, 100, 7, 2},
		Value: encodedValue,
	}
	return &groupListExtension, nil
}

func makeServiceMethodListExtension(serviceMethods []string) (
	*pkix.Extension, error) {
	if len(serviceMethods) < 1 {
		return nil, nil
	}
	encodedValue, err := asn1.Marshal(serviceMethods)
	if err != nil {
		return nil, err
	}
	serviceMethodListExtension := pkix.Extension{
		// See github.com/Cloud-Foundations/Dominator/lib/constants.PermittedMethodListOID
		Id:    []int{1, 3, 6, 1, 4, 1, 9586, 100, 7, 1},
		Value: encodedValue,
	}
	return &serviceMethodListExtension, nil
}

// returns an x509 cert that has the username in the common name,
// optionally if a kerberos Realm is present it will also add a kerberos
// SAN exention for pkinit
func GenUserX509Cert(userName string, userPub interface{},
	caCert *x509.Certificate, caPriv crypto.Signer,
	kerberosRealm *string, duration time.Duration,
	groups, organizations, serviceMethods []string,
	logger log.DebugLogger) ([]byte, error) {
	//// Now do the actual work...
	notBefore := time.Now()
	notAfter := notBefore.Add(duration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	sanExtension, err := genSANExtension(userName, kerberosRealm)
	if err != nil {
		return nil, err
	}

	// Need to add the extended key usage... that is special for kerberos
	// and also the client key usage.
	kerberosClientExtKeyUsage := []int{1, 3, 6, 1, 5, 2, 3, 4}
	subject := pkix.Name{
		CommonName:   userName,
		Organization: organizations,
	}
	groupListExtension, err := makeGroupListExtension(groups)
	if err != nil {
		return nil, err
	}
	serviceMethodListExtension, err := makeServiceMethodListExtension(
		serviceMethods)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{kerberosClientExtKeyUsage},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	addExtraExtension(&template, groupListExtension, "group list", logger)
	addExtraExtension(&template, serviceMethodListExtension, "service methods",
		logger)
	addExtraExtension(&template, sanExtension, "Kerberos SAN", logger)

	return x509.CreateCertificate(rand.Reader, &template, caCert, userPub, caPriv)
}
