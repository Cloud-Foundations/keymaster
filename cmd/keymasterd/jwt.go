package main

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// This actually gets the SSH key fingerprint
func getKeyFingerprint(key crypto.PublicKey) (string, error) {
	sshPublicKey, err := ssh.NewPublicKey(key)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(sshPublicKey.Marshal())
	fp := fmt.Sprintf("%x", h.Sum(nil))
	return fp, nil
}

func (state *RuntimeState) idpGetIssuer() string {
	issuer := "https://" + state.HostIdentity
	if state.Config.Base.HttpAddress != ":443" {
		issuer = issuer + state.Config.Base.HttpAddress
	}
	return issuer
}

func (state *RuntimeState) JWTClaims(t *jwt.JSONWebToken, dest ...interface{}) (err error) {
	for _, key := range state.KeymasterPublicKeys {
		err = t.Claims(key, dest...)
		if err == nil {
			return nil
		}
	}
	if err != nil {
		return err
	}
	err = errors.New("No valid key found")
	return err
}

func (state *RuntimeState) genNewSerializedAuthJWT(username string,
	authLevel int, durationSeconds int64) (string, error) {
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: state.Signer}, signerOptions)
	if err != nil {
		return "", err
	}
	issuer := state.idpGetIssuer()
	authToken := authInfoJWT{Issuer: issuer, Subject: username,
		Audience: []string{issuer}, AuthType: authLevel, TokenType: "keymaster_auth"}
	authToken.NotBefore = time.Now().Unix()
	authToken.IssuedAt = authToken.NotBefore
	authToken.Expiration = authToken.IssuedAt + durationSeconds
	return jwt.Signed(signer).Claims(authToken).CompactSerialize()
}

func (state *RuntimeState) getAuthInfoFromAuthJWT(serializedToken string) (
	rvalue authInfo, err error) {
	return state.getAuthInfoFromJWT(serializedToken, "keymaster_auth")
}

func (state *RuntimeState) getAuthInfoFromJWT(serializedToken,
	tokenType string) (rvalue authInfo, err error) {
	tok, err := jwt.ParseSigned(serializedToken)
	if err != nil {
		return rvalue, err
	}
	inboundJWT := authInfoJWT{}
	if err := state.JWTClaims(tok, &inboundJWT); err != nil {
		logger.Printf("err=%s", err)
		return rvalue, err
	}
	//At this stage is now crypto verified, now is time to verify sane values
	issuer := state.idpGetIssuer()
	if inboundJWT.Issuer != issuer || inboundJWT.TokenType != tokenType ||
		len(inboundJWT.Audience) < 1 || inboundJWT.Audience[0] != issuer ||
		inboundJWT.NotBefore > time.Now().Unix() {
		err = errors.New("invalid JWT values")
		return rvalue, err
	}
	rvalue.AuthType = inboundJWT.AuthType
	rvalue.ExpiresAt = time.Unix(inboundJWT.Expiration, 0)
	rvalue.IssuedAt = time.Unix(inboundJWT.IssuedAt, 0)
	rvalue.Username = inboundJWT.Subject
	return rvalue, nil
}

func (state *RuntimeState) updateAuthJWTWithNewAuthLevel(intoken string, newAuthLevel int) (string, error) {
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: state.Signer}, signerOptions)
	if err != nil {
		return "", err
	}

	tok, err := jwt.ParseSigned(intoken)
	if err != nil {
		return "", err
	}
	parsedJWT := authInfoJWT{}
	if err := state.JWTClaims(tok, &parsedJWT); err != nil {
		logger.Printf("err=%s", err)
		return "", err
	}
	issuer := state.idpGetIssuer()
	if parsedJWT.Issuer != issuer || parsedJWT.TokenType != "keymaster_auth" ||
		len(parsedJWT.Audience) < 1 || parsedJWT.Audience[0] != issuer ||
		parsedJWT.NotBefore > time.Now().Unix() {
		err = errors.New("invalid JWT values")
		return "", err
	}
	parsedJWT.AuthType = newAuthLevel
	return jwt.Signed(signer).Claims(parsedJWT).CompactSerialize()
}

func (state *RuntimeState) genNewSerializedStorageStringDataJWT(username string, dataType int, data string, expiration int64) (string, error) {
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: state.Signer}, signerOptions)
	if err != nil {
		return "", err
	}
	issuer := state.idpGetIssuer()
	storageToken := storageStringDataJWT{Issuer: issuer, Subject: username,
		Audience: []string{issuer}, DataType: dataType,
		TokenType: "storage_data", Data: data}
	storageToken.NotBefore = time.Now().Unix()
	storageToken.IssuedAt = storageToken.NotBefore
	storageToken.Expiration = expiration

	return jwt.Signed(signer).Claims(storageToken).CompactSerialize()
}

func (state *RuntimeState) getStorageDataFromStorageStringDataJWT(serializedToken string) (rvalue storageStringDataJWT, err error) {
	tok, err := jwt.ParseSigned(serializedToken)
	if err != nil {
		return rvalue, err
	}
	inboundJWT := storageStringDataJWT{}
	if err := state.JWTClaims(tok, &inboundJWT); err != nil {
		logger.Printf("err=%s", err)
		return rvalue, err
	}
	// At this stage crypto has been verified (data actually comes from a valid signer),
	// Now is time to do semantic validation
	issuer := state.idpGetIssuer()
	if inboundJWT.Issuer != issuer || inboundJWT.TokenType != "storage_data" ||
		len(inboundJWT.Audience) < 1 || inboundJWT.Audience[0] != issuer ||
		inboundJWT.NotBefore > time.Now().Unix() {
		err = errors.New("invalid JWT values")
		return rvalue, err
	}
	return inboundJWT, nil
}
