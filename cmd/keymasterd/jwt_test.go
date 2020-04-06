package main

import (
	"os"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func testONLYGenerateAuthJWT(state *RuntimeState, username string, authLevel int, issuer string, audience []string) (string, error) {
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: state.Signer}, signerOptions)
	if err != nil {
		return "", err
	}
	authToken := authInfoJWT{Issuer: issuer, Subject: username,
		Audience: audience, AuthType: authLevel, TokenType: "keymaster_auth"}
	authToken.NotBefore = time.Now().Unix()
	authToken.IssuedAt = authToken.NotBefore
	authToken.Expiration = authToken.IssuedAt + maxAgeSecondsAuthCookie // TODO seek the actual duration
	return jwt.Signed(signer).Claims(authToken).CompactSerialize()
}

func TestJWTAudtienceAuthToken(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
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
