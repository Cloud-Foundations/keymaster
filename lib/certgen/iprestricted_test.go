package certgen

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
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

/*
// This test should be a forward test to ensure that we encode into well
// known encoding values
func TestGenenDelegationExtensionInterop(t *testing.T) {


}
*/

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
	_, netblock6, err := net.ParseCIDR("192.168.24.0/24")
	if err != nil {
		t.Fatal(err)
	}
	netblock7 := net.IPNet{
		//IP:   net.ParseIP("2001:0:200:3:0:0:0:1"),
		IP:   net.ParseIP("2001:0:200:3:0:0:1:1"),
		Mask: net.CIDRMask(128, 128),
	}
	netblock8 := net.IPNet{
		IP:   net.ParseIP("2001:0:200::"),
		Mask: net.CIDRMask(39, 128),
	}
	netblock9 := net.IPNet{
		IP:   net.ParseIP("2001::"),
		Mask: net.CIDRMask(32, 128),
	}
	_, netblock10, err := net.ParseCIDR("2001:db8:a0b:12f0::1/32")
	if err != nil {
		t.Fatal(err)
	}

	netblockListList := [][]net.IPNet{
		{netblock, netblock2},
		{netblock},
		{netblock3},
		{netblock5, netblock4},
		{*netblock6},
		{netblock7},
		{netblock8},
		{netblock9},
		{*netblock10},
		{netblock5, netblock4, netblock8},
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

		roundTripBlockList, err := decodeDelegationExtension(extension)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("%+v", roundTripBlockList)
		if len(roundTripBlockList) != len(netblockList) {
			t.Fatal(errors.New("bad rountrip lenght"))
		}
		for i, block := range netblockList {
			if !block.IP.Equal(roundTripBlockList[i].IP) {
				t.Fatal(fmt.Errorf("ip not matching %d %s %s", i, block.IP.String(), (roundTripBlockList[i].String())))

			}
			if block.Mask.String() != roundTripBlockList[i].Mask.String() {
				t.Fatal(fmt.Errorf("masks do not match  not matching %d %s %s", i, block.Mask.String(), (roundTripBlockList[i].String())))
			}
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
	_, netblock3, err := net.ParseCIDR("192.168.24.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, netblock4, err := net.ParseCIDR("2001:db8:a0b:12f0::1/32")
	if err != nil {
		t.Fatal(err)
	}

	netblockList := []net.IPNet{netblock, netblock2, *netblock3, *netblock4}
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

func TestDecodeIPV4AddressChoiceFail(t *testing.T) {
	negativeBitLength := asn1.BitString{
		BitLength: -1,
	}
	zeroBitLenght := asn1.BitString{
		BitLength: 0,
	}
	tooLargeBitLenght := asn1.BitString{
		BitLength: 33,
	}

	failBitStrings := []asn1.BitString{negativeBitLength, zeroBitLenght, tooLargeBitLenght}
	for _, block := range failBitStrings {
		_, err := decodeIPV4AddressChoice(block)
		if err == nil {
			t.Fatalf("should have failed")
		}
	}
	//not failing, but inconsistent
	tooSmallBytes1 := asn1.BitString{
		BitLength: 15,
		Bytes:     []byte{0x03},
	}
	tooManyBytes1 := asn1.BitString{
		BitLength: 7,
		Bytes:     []byte{0x03, 0xf3},
	}
	inconsistentBitStrings := []asn1.BitString{tooSmallBytes1, tooManyBytes1}
	for _, block := range inconsistentBitStrings {
		_, err := decodeIPV4AddressChoice(block)
		if err != nil {
			t.Fatalf("should NOT have failed")
		}
	}
}

func TestDecodeDelegationExtensionFail(t *testing.T) {
	invalidASN1Master := pkix.Extension{
		Id:    oidIPAddressDelegation,
		Value: []byte{0x30, 0x0e, 0x30, 0x0c, 0x04},
	}
	uknownAddrFamily := pkix.Extension{
		Id:    oidIPAddressDelegation,
		Value: []byte{0x30, 0x0e, 0x30, 0x0c, 0x04, 0x03, 0x00, 0x01, 0x02, 0x30, 0x05, 0x03, 0x03, 00, 0x0d, 0xff},
	}
	invalidASN1Range := pkix.Extension{
		Id:    oidIPAddressDelegation,
		Value: []byte{0x30, 0x0e, 0x30, 0x0c, 0x04, 0x03, 0x00, 0x01, 0x01, 0x30, 0x05, 0x03, 0x04, 00, 0x0d, 0xff},
	}
	// Next is an ipv6 address encoded with an ipv4 family...should NOT decode
	//30 14 30 12 04 03 00 01  01 30 0b 03 09 00 20 01  |0.0......0.... .|
	//00 00 02 00 00 03

	failExtensions := []pkix.Extension{invalidASN1Master, uknownAddrFamily, invalidASN1Range}
	for _, extension := range failExtensions {
		_, err := decodeDelegationExtension(&extension)
		if err == nil {
			t.Fatalf("should have failed")
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
	f.Add(int8(15), []byte{0x03, 0xf4})
	f.Add(int8(22), []byte{0x01, 0x02, 0x03})
	f.Add(int8(-1), []byte{0x03, 0xf4})
	f.Fuzz(func(t *testing.T, bitLength int8, encValue []byte) {
		encodedBlock := asn1.BitString{
			BitLength: int(bitLength),
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

func FuzzDecodeIPV6AddressChoice(f *testing.F) {
	f.Add(int16(15), []byte{0x03, 0xf4})
	f.Add(int16(22), []byte{0x01, 0x02, 0x03})
	f.Add(int16(-1), []byte{0x03, 0xf4})
	f.Add(int16(32), []byte{0x03, 0x05, 0x00, 0x20, 0x01, 00, 0x00})
	f.Add(int16(129), []byte{0x03, 0x05, 0x00, 0x20, 0x01, 00, 0x00})
	f.Fuzz(func(t *testing.T, bitLength int16, encValue []byte) {
		encodedBlock := asn1.BitString{
			BitLength: int(bitLength),
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
