package main

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	passPhrase := "1234"
	inData := "123456781234567"
	var plaintextBuffer bytes.Buffer
	_, err := plaintextBuffer.Write([]byte(inData))
	if err != nil {
		t.Fatal(err)
	}
	armoredBytes, err := armorEncryptBytes(plaintextBuffer.Bytes(), []byte(passPhrase))
	if err != nil {
		t.Fatal(err)
	}
	outData, err := pgpDecryptFileData(armoredBytes, []byte(passPhrase))
	if err != nil {
		t.Fatal(err)
	}
	equal := bytes.Equal([]byte(inData), outData)
	if !equal {
		t.Fatal("roundtrip fail")
	}

}
