package cryptoutils

import (
	"bytes"
	"testing"

	"github.com/Cloud-Foundations/keymaster/lib/certgen"
)

// symmtrically gpg encrypted ED25519 private key with password "password"
// openssl genpkey  -algorithm ED25519 -out ed25519.pem
// gpg --symmetric --cipher-algo AES256 --armor ed_25519.pem
const encryptedTestEd25519PrivateKey = `-----BEGIN PGP MESSAGE-----

jA0ECQMCoPd2XFiFYsX/0p8B1yj+/IkHDf5vQcmCo5W2D/iW2JfWpymSNKCvtXdW
m+ycZoG7b1+m/ybqM/plBv1n7t9+53yzVdwhB1mMFVYKvGAYmbiQIdme8pJwY4vy
VKKOvkE6n1XtjsKrQVh+om9rort85dI+YzU/py17b5Vm4NKbQdUi0DQPLYk2djEK
TZefF/kZQbQUhZY7E9Dj3wqUwIcixVTanxSXg3Et3Uo=
=tKeJ
-----END PGP MESSAGE-----`

func TestDecryptFail(t *testing.T) {
	_, err := PGPDecryptArmoredBytes([]byte(encryptedTestEd25519PrivateKey), []byte("badpassword"))
	if err == nil {
		t.Fatalf("not failed with bad password")
	}
	_, err = PGPDecryptArmoredBytes([]byte("-----BEGIN PGP MESSAGE-----"), []byte("badpassword"))
	if err == nil {
		t.Fatalf("not failed with bad data")
	}
}

func TestDecryptSuccess(t *testing.T) {
	pemKey, err := PGPDecryptArmoredBytes([]byte(encryptedTestEd25519PrivateKey), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = certgen.GetSignerFromPEMBytes(pemKey)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	passPhrase := "1234"
	inData := "123456781234567"
	var plaintextBuffer bytes.Buffer
	_, err := plaintextBuffer.Write([]byte(inData))
	if err != nil {
		t.Fatal(err)
	}
	armoredBytes, err := PGPArmorEncryptBytes(plaintextBuffer.Bytes(), []byte(passPhrase))
	if err != nil {
		t.Fatal(err)
	}
	outData, err := PGPDecryptArmoredBytes(armoredBytes, []byte(passPhrase))
	if err != nil {
		t.Fatal(err)
	}
	equal := bytes.Equal([]byte(inData), outData)
	if !equal {
		t.Fatal("roundtrip fail")
	}

}
