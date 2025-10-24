package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func testPublicToPreferedJoseSigAlgo(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	algo, err := publicToPreferedJoseSigAlgo(p256Key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if algo != jose.ES256 {
		t.Fatalf("alg does not match P256")
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	algo, err = publicToPreferedJoseSigAlgo(p384Key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if algo != jose.ES384 {
		t.Fatalf("alg does not match P384")
	}

}

func testONLYGenerateAuthJWT(state *RuntimeState, username string, authLevel int, issuer string, audience []string) (string, error) {
	signer, err := getJoseSignerFromSigner(state.Signer)
	if err != nil {
		return "", err
	}
	authToken := authInfoJWT{Issuer: issuer, Subject: username,
		Audience: audience, AuthType: authLevel, TokenType: "keymaster_auth"}
	authToken.NotBefore = time.Now().Unix()
	authToken.IssuedAt = authToken.NotBefore
	authToken.Expiration = authToken.IssuedAt + maxAgeSecondsAuthCookie // TODO seek the actual duration
	return jwt.Signed(signer).Claims(authToken).Serialize()
}

func TestJWTAudtienceAuthToken(t *testing.T) {
	privatePEM := []string{testSignerPrivateKey, pkcs8ecPrivateKey} // thats rsa, p384

	for _, private := range privatePEM {
		state, passwdFile, err := setupValidRuntimeStateSignerGeneric(private, t)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(passwdFile.Name()) // clean up
		issuer := state.idpGetIssuer()
		goodToken, err := testONLYGenerateAuthJWT(state, "username", AuthTypeU2F, issuer, []string{issuer})
		if err != nil {
			t.Fatal(err)
		}
		_, err = state.getAuthInfoFromAuthJWT(goodToken)
		if err != nil {
			t.Fatal(err)
		}
		badTokenIncorrectAudience, err := testONLYGenerateAuthJWT(state, "username", AuthTypeU2F, issuer, []string{"otherAudience"})
		_, err = state.getAuthInfoFromAuthJWT(badTokenIncorrectAudience)
		if err == nil {
			t.Fatal("Should have failed for mismatching audience")
		}
		badTokenEmptyAudience, err := testONLYGenerateAuthJWT(state, "username", AuthTypeU2F, issuer, []string{})
		_, err = state.getAuthInfoFromAuthJWT(badTokenEmptyAudience)
		if err == nil {
			t.Fatal("Should have failed for mismatching audience")
		}
	}
}

func TestMixedKeyTypeSigners(t *testing.T) {
	privatePEM := []string{testSignerPrivateKey, pkcs8ecPrivateKey} // thats rsa, p384

	var keymasterSetups []*RuntimeState
	for _, private := range privatePEM {
		km, passwdFile, err := setupValidRuntimeStateSignerGeneric(private, t)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(passwdFile.Name())
		keymasterSetups = append(keymasterSetups, km)
	}
	// append other publics to trusted
	for i, km := range keymasterSetups {
		for j, km2 := range keymasterSetups {
			if i != j {
				km.KeymasterPublicKeys = append(km.KeymasterPublicKeys, km2.Signer.Public())
			}
		}
	}
	// now the actual test
	for _, km := range keymasterSetups {
		issuer := km.idpGetIssuer()
		goodToken, err := testONLYGenerateAuthJWT(km, "username", AuthTypeU2F, issuer, []string{issuer})
		if err != nil {
			t.Fatal(err)
		}
		badTokenIncorrectAudience, err := testONLYGenerateAuthJWT(km, "username",
			AuthTypeU2F, issuer, []string{"otherAudience"})
		if err != nil {
			t.Fatal(err)
		}
		for _, km2 := range keymasterSetups {
			_, err = km2.getAuthInfoFromAuthJWT(goodToken)
			if err != nil {
				t.Fatal(err)
			}
			_, err = km2.getAuthInfoFromAuthJWT(badTokenIncorrectAudience)
			if err == nil {
				t.Fatal("should have failed")
			}
		}
	}

}
