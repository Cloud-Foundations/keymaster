package certgen

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	//"log"
	"math/big"
	"net"
	"time"
)

//We aim to build certs compatible with
// https://tools.ietf.org/html/rfc3779

type IpAdressFamily struct {
	AddressFamily []byte
	Addresses     []asn1.BitString
}

var oidIPAddressDelegation = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 7}
var ipV4FamilyEncoding = []byte{0, 1, 1}

//For now ipv4 only
func encodeIpAddressChoice(netBlock net.IPNet) (asn1.BitString, error) {
	ones, bits := netBlock.Mask.Size()
	if bits != 32 {
		return asn1.BitString{}, errors.New("not an ipv4 address")
	}
	//unusedLen = uint8(ones) % 8
	var output []byte
	outlen := ((ones + 7) / 8)
	//log.Printf("outlen=%d, ones=%d", outlen, ones)
	output = make([]byte, outlen, outlen)
	//log.Printf("len netbloclen=%+v,", len(netBlock.IP))
	increment := 12
	if len(netBlock.IP) == 4 {
		increment = 0
	}
	for i := 0; i < outlen; i++ {
		output[i] = netBlock.IP[increment+i]
	}
	//log.Printf("%+v", output)
	bitString := asn1.BitString{
		Bytes:     output,
		BitLength: ones,
	}

	return bitString, nil
}

func genDelegationExtension(ipv4Netblocks []net.IPNet) (*pkix.Extension, error) {
	ipv4AddressFamily := IpAdressFamily{
		AddressFamily: ipV4FamilyEncoding,
	}
	for _, netblock := range ipv4Netblocks {
		encodedNetBlock, err := encodeIpAddressChoice(netblock)
		if err != nil {
			return nil, err
		}
		ipv4AddressFamily.Addresses = append(ipv4AddressFamily.Addresses, encodedNetBlock)
	}
	addressFamilyList := []IpAdressFamily{ipv4AddressFamily}

	encodedAddressFamily, err := asn1.Marshal(addressFamilyList)
	if err != nil {
		return nil, err
	}
	ipDelegationExtension := pkix.Extension{
		Id:    oidIPAddressDelegation,
		Value: encodedAddressFamily,
	}
	return &ipDelegationExtension, nil
}

func decodeIPV4AddressChoice(encodedBlock asn1.BitString) (net.IPNet, error) {
	var encodedIP [4]byte
	for i := 0; (i * 8) < encodedBlock.BitLength; i++ {
		encodedIP[i] = encodedBlock.Bytes[i]
	}
	netBlock := net.IPNet{
		IP:   net.IPv4(encodedIP[0], encodedIP[1], encodedIP[2], encodedIP[3]),
		Mask: net.CIDRMask(encodedBlock.BitLength, 32),
	}
	return netBlock, nil
}

//
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// ComputePublicKeyKeyID computes the SHA-1 digest of a public Key
func ComputePublicKeyKeyID(PublicKey interface{}) ([]byte, error) {
	encodedPub, err := x509.MarshalPKIXPublicKey(PublicKey)
	if err != nil {
		return nil, err
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, err
	}

	pubHash := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
	return pubHash[:], nil
}

// GenIPRestrictedX509Cert returns an x509 cert that has the username in
// the common name, with the allowed netyblocks specified
func GenIPRestrictedX509Cert(userName string, userPub interface{},
	caCert *x509.Certificate, caPriv crypto.Signer,
	ipv4Netblocks []net.IPNet, duration time.Duration,
	crlURL []string, OCPServer []string) ([]byte, error) {
	// Now do the actual work...
	notBefore := time.Now()
	notAfter := notBefore.Add(duration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	subject := pkix.Name{
		CommonName: userName,
	}
	ipDelegationExtension, err := genDelegationExtension(ipv4Netblocks)
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
		IssuingCertificateURL: crlURL,
		OCSPServer:            OCPServer,
		BasicConstraintsValid: true,
		IsCA: false,
	}
	if ipDelegationExtension != nil {
		template.ExtraExtensions = append(template.ExtraExtensions,
			*ipDelegationExtension)
	}
	return x509.CreateCertificate(rand.Reader, &template, caCert, userPub, caPriv)
}

// VerifyIPRestrictedX509CertIP takes a x509 cert and verifies that it is valid given
// an incoming remote address. If the cert does not contain an IP restriction extension
// the verification is considered failed.
func VerifyIPRestrictedX509CertIP(userCert *x509.Certificate, remoteAddr string) (bool, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false, err
	}
	remoteIP := net.ParseIP(host)
	var extension *pkix.Extension = nil
	for _, certExtension := range userCert.Extensions {
		if certExtension.Id.Equal(oidIPAddressDelegation) {
			extension = &certExtension
			break
		}
	}
	if extension == nil {
		return false, nil
	}
	var ipAddressFamilyList []IpAdressFamily
	_, err = asn1.Unmarshal(extension.Value, &ipAddressFamilyList)
	if err != nil {
		return false, err
	}
	for _, addressList := range ipAddressFamilyList {
		if !bytes.Equal(addressList.AddressFamily, ipV4FamilyEncoding) {
			continue
		}
		for _, encodedNetblock := range addressList.Addresses {
			decoded, err := decodeIPV4AddressChoice(encodedNetblock)
			if err != nil {
				return false, err
			}
			if decoded.Contains(remoteIP) {
				return true, nil
			}
		}
	}
	return false, nil
}
