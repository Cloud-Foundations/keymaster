package main

import (
	"testing"
)

func TestSignersGenerate(t *testing.T) {
	var err error
	signers := makeSigners()
	signers.compute()
	err = signers.Wait()
	if err != nil {
		t.Fatal(err)
	}
	signers2 := makeSigners()
	signers2.keyPref = P256Signer
	signers2.compute()
	err = signers2.Wait()
	if err != nil {
		t.Fatal(err)
	}
}
