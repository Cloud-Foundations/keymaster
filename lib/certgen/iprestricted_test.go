package certgen

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"net"
	"testing"
)

func TestComputePublicKeyKeyID(t *testing.T) {
	userPub, _, _ := setupX509Generator(t)
	_, err := ComputePublicKeyKeyID(userPub)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenDelegationExtension(t *testing.T) {

	netblock := net.IPNet{
		IP:   net.ParseIP("10.11.12.0"),
		Mask: net.CIDRMask(24, 32),
	}
	netblock2 := net.IPNet{
		IP:   net.ParseIP("13.14.128.0"),
		Mask: net.CIDRMask(20, 32),
	}
	netblockList := []net.IPNet{netblock, netblock2}
	var extension *pkix.Extension
	var err error
	extension, err = genDelegationExtension(netblockList)
	if err != nil {
		t.Fatal(err)
	}
	extensionDer, err := asn1.Marshal(*extension)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("encodedExt=\n%s", hex.Dump(extensionDer))
	var addressFamilyList []IpAdressFamily
	_, err = asn1.Unmarshal(extension.Value, &addressFamilyList)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", addressFamilyList)
	var roundTripBlockList []net.IPNet
	for _, encodedNetblock := range addressFamilyList[0].Addresses {
		decoded, err := decodeIPV4AddressChoice(encodedNetblock)
		if err != nil {
			t.Fatal(err)
		}
		roundTripBlockList = append(roundTripBlockList, decoded)
	}
	t.Logf("%+v", roundTripBlockList)
	if len(roundTripBlockList) != len(netblockList) {
		t.Fatal(errors.New("bad rountrip lenght"))
	}

}

func TestGenIPRestrictedX509Cert(t *testing.T) {
	userPub, caCert, caPriv := setupX509Generator(t)
	netblock := net.IPNet{
		IP:   net.ParseIP("127.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblock2 := net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblockList := []net.IPNet{netblock, netblock2}
	derCert, err := GenIPRestrictedX509Cert("username", userPub, caCert, caPriv, netblockList, testDuration, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := derBytesCertToCertAndPem(derCert)
	if err != nil {
		t.Fatal(err)
	}
	//t.Logf("%+v", cert)
	var ok bool
	ok, err = VerifyIPRestrictedX509CertIP(cert, "10.0.0.1:234")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("should have passed")
	}
	ok, err = VerifyIPRestrictedX509CertIP(cert, "1.1.1.1:234")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("should have failed bad ip range")
	}
	ok, err = VerifyIPRestrictedX509CertIP(caCert, "1.1.1.1:234")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("should have failed extension not found")
	}
}

func TestExtractIPNetsFromIPRestrictedX509(t *testing.T) {
	userPub, caCert, caPriv := setupX509Generator(t)
	netblock := net.IPNet{
		IP:   net.ParseIP("127.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblock2 := net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblockList := []net.IPNet{netblock, netblock2}
	derCert, err := GenIPRestrictedX509Cert("username", userPub, caCert, caPriv, netblockList, testDuration, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := derBytesCertToCertAndPem(derCert)
	if err != nil {
		t.Fatal(err)
	}
	certNets, err := ExtractIPNetsFromIPRestrictedX509(cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(certNets) != len(netblockList) {
		t.Fatalf("lenghts should match")
	}
	for i, certNet := range certNets {
		if certNet.String() != netblockList[i].String() {
			t.Fatalf("nets dont match")
		}
	}
}
