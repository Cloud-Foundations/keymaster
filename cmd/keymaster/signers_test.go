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
		err = signers.Wait()
		if err != nil {
			t.Fatal(err)
		}
		// TODO: actually check the singers match
		// the preference
	}
}

func TestKeyPreferenceFromString(t *testing.T) {
	GoodKeyPreferences := []string{"rsa", "p256", "p384"}
	for _, keyPref := range GoodKeyPreferences {
		_, err := keyPreferenceFromString(keyPref)
		if err != nil {
			t.Fatal(err)
		}
	}
	BadKeyPreferences := []string{"foobar", "", "x445"}
	for _, keyPref := range BadKeyPreferences {
		_, err := keyPreferenceFromString(keyPref)
		if err == nil {
			t.Fatalf("should have failed")
		}
	}
}
