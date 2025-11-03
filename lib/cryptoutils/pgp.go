package cryptoutils

import (
	"bytes"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func PGPDecryptArmoredBytes(cipherText []byte, password []byte) ([]byte, error) {
	decbuf := bytes.NewBuffer(cipherText)
	armorBlock, err := armor.Decode(decbuf)
	if err != nil {
		return nil, fmt.Errorf("cannot decode armored file")
	}
	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		// If the given passphrase isn't correct, the function will be called
		// again, forever.
		// This method will fail fast.
		// Ref: https://godoc.org/golang.org/x/crypto/openpgp#PromptFunction
		if failed {
			return nil, fmt.Errorf("decryption failed")
		}
		failed = true
		return password, nil
	}
	md, err := openpgp.ReadMessage(armorBlock.Body, nil, prompt, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt key: %s", err)
	}
	return io.ReadAll(md.UnverifiedBody)
}

func PGPArmorEncryptBytes(plaintext []byte, passphrase []byte) ([]byte, error) {
	encryptionType := "PGP MESSAGE"
	armoredBuf := new(bytes.Buffer)
	armoredWriter, err := armor.Encode(armoredBuf, encryptionType, nil)
	if err != nil {
		return nil, err
	}
	var plaintextWriter io.WriteCloser
	plaintextWriter, err = openpgp.SymmetricallyEncrypt(armoredWriter,
		passphrase, nil, nil)
	if err != nil {
		return nil, err
	}
	_, err = plaintextWriter.Write(plaintext)
	if err != nil {
		return nil, err
	}
	if err := plaintextWriter.Close(); err != nil {
		return nil, err
	}
	if err := armoredWriter.Close(); err != nil {
		return nil, err
	}
	return armoredBuf.Bytes(), nil
}
