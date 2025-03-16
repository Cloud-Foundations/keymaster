package main

import (
	"testing"
)

func TestSignersGenerate(t *testing.T) {
	KeyPreferences := []string{"rsa", "p256", "p384"}
	for _, keyPref := range KeyPreferences {
		keyType, err := keyPreferenceFromString(keyPref)
		if err != nil {
			t.Fatal(err)
		}
		signers := makeSigners(keyType)
		signers.compute()
		err = signers.Wait()
		if err != nil {
			t.Fatal(err)
		}
	}
	/*
		signers2 := makeSigners()
		signers2.keyPref = P256Signer
		signers2.compute()
		err = signers2.Wait()
		if err != nil {
			t.Fatal(err)
		}
	*/
}
