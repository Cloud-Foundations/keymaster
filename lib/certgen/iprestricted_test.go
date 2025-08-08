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
	netblock3 := net.IPNet{
		IP:   net.ParseIP("13.255.0.0"),
		Mask: net.CIDRMask(16, 32),
	}
	netblock4 := net.IPNet{
		IP:   net.ParseIP("172.16.0.0"),
		Mask: net.CIDRMask(12, 32),
	}
	netblock5 := net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}

	netblockListList := [][]net.IPNet{
		{netblock, netblock2},
		{netblock},
		{netblock3},
		{netblock5, netblock4},
	}

	for _, netblockList := range netblockListList {
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
		t.Logf("ExtValue=\n%s", hex.Dump(extension.Value))
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
	cert, pemCert, err := derBytesCertToCertAndPem(derCert)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Ip restricted cert%+v", pemCert)
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

func FuzzDecodeExtensionValue(f *testing.F) {
	//f.Add([]byte{0x30, 0x0e, 0x30, 0x0c, 0x04}) // 03 00 01  01 30 05 03 03 00 0d ff})
	// NOTE the added data looks like it needs to succeed
	f.Add([]byte{0x30, 0x0e, 0x30, 0x0c, 0x04, 0x03, 0x00, 0x01, 0x01, 0x30, 0x05, 0x03, 0x03, 00, 0x0d, 0xff})
	f.Add([]byte{0x30, 0x0f, 0x30, 0x0d, 0x04, 0x03, 0x00, 0x01, 0x01, 0x30, 0x06, 0x03, 0x04, 00, 0x0a, 0x0b, 0x0c})
	f.Fuzz(func(t *testing.T, extValue []byte) {
		extension := pkix.Extension{
			Id:    oidIPAddressDelegation,
			Value: extValue,
		}
		out, err := decodeDelegationExtension(&extension)
		if err != nil && out != nil {
			t.Errorf("%q, %v", out, err)
		}
	})
}

func FuzzDecodeIPV4AddressChoice(f *testing.F) {
	f.Add(15, []byte{0x03, 0xf4})
	f.Add(22, []byte{0x01, 0x02, 0x03})
	f.Add(-1, []byte{0x03, 0xf4})
	f.Fuzz(func(t *testing.T, bitLength int, encValue []byte) {
		encodedBlock := asn1.BitString{
			BitLength: bitLength,
			Bytes:     encValue,
		}
		//emptyNet := net.IPNet{}
		out, err := decodeIPV4AddressChoice(encodedBlock)
		if err != nil {
			if out.IP != nil {
				t.Errorf("%q, %v", out, err)
			}
		}

	})
}
