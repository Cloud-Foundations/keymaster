/*
  Package certgen id set of utilities used to generate ssh certificates
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

	"golang.org/x/crypto/ssh"
)

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
	fileComment := "/tmp/" + username + "-cert.pub"
	return "ssh-rsa-cert-v01@openssh.com " + encoded + " " + fileComment, nil
}

// gen_user_cert a username and key, returns a short lived cert for that user
func GenSSHCertFileString(username string, userPubKey string, signer ssh.Signer, host_identity string, duration time.Duration) (string, []byte, error) {
	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(userPubKey))
	if err != nil {
		return "", nil, err
	}
	keyIdentity := host_identity + "_" + username

	currentEpoch := uint64(time.Now().Unix())
	expireEpoch := currentEpoch + uint64(duration.Seconds())

	nBig, err := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFF))
	if err != nil {
		return "", nil, err
	}
	serial := (currentEpoch << 32) | nBig.Uint64()

	// The values of the permissions are taken from the default values used
	// by ssh-keygen
	cert := ssh.Certificate{
		Key:             userKey,
		CertType:        ssh.UserCert,
		SignatureKey:    signer.PublicKey(),
		ValidPrincipals: []string{username},
		KeyId:           keyIdentity,
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
		Serial:          serial,
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-X11-forwarding":   "",
			"permit-agent-forwarding": "",
			"permit-port-forwarding":  "",
			"permit-pty":              "",
			"permit-user-rc":          ""}}}

	err = cert.SignCert(bytes.NewReader(cert.Marshal()), signer)
	if err != nil {
		return "", nil, err
	}
	certString, err := goCertToFileString(cert, username)
	if err != nil {
		return "", nil, err
	}
	return certString, cert.Marshal(), nil
}

func GenSSHCertFileStringFromSSSDPublicKey(userName string, signer ssh.Signer, hostIdentity string, duration time.Duration) (string, []byte, error) {

	userPubKey, err := GetUserPubKeyFromSSSD(userName)
	if err != nil {
		return "", nil, err
	}
	cert, certBytes, err := GenSSHCertFileString(userName, userPubKey, signer, hostIdentity, duration)
	if err != nil {
		return "", nil, err
	}
	return cert, certBytes, err
}

/// X509 section
func getPubKeyFromPem(pubkey string) (pub interface{}, err error) {
	block, rest := pem.Decode([]byte(pubkey))
	if block == nil || block.Type != "PUBLIC KEY" {
		err := errors.New(fmt.Sprintf("Cannot decode user public Key '%s' rest='%s'", pubkey, string(rest)))
		if block != nil {
			err = errors.New(fmt.Sprintf("public key bad type %s", block.Type))
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
		default:
			return nil, fmt.Errorf("Type not recognized  %T!\n", v)
		}
	default:
		err := errors.New("Cannot process that key")
		return nil, err
	}
}

//copied from https://golang.org/src/crypto/tls/generate_cert.go
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	// TODO: eventaully we need to suport ecdsa for CA
	// case *ecdsa.PrivateKey:
	//	return &k.PublicKey
	default:
		return nil
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
	sum := sha256.Sum256([]byte(commonName))
	signedCN, err := caPriv.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	sigSum := sha256.Sum256(signedCN)
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

	return x509.CreateCertificate(rand.Reader, &template, &template, publicKey(caPriv), caPriv)
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

func getGroupListExtension(groups []string) (*pkix.Extension, error) {
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

// returns an x509 cert that has the username in the common name,
// optionally if a kerberos Realm is present it will also add a kerberos
// SAN exention for pkinit
func GenUserX509Cert(userName string, userPub interface{},
	caCert *x509.Certificate, caPriv crypto.Signer,
	kerberosRealm *string, duration time.Duration,
	groups []string, organizations []string) ([]byte, error) {
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
	groupListExtension, err := getGroupListExtension(groups)
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
	if groupListExtension != nil {
		template.ExtraExtensions = append(template.ExtraExtensions,
			*groupListExtension)
	}
	if sanExtension != nil {
		template.ExtraExtensions = append(template.ExtraExtensions,
			*sanExtension)
	}

	return x509.CreateCertificate(rand.Reader, &template, caCert, userPub, caPriv)
}
