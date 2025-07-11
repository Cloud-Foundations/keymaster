package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// This is the implementation of duo-labs' webauthn User interface
// https://github.com/duo-labs/webauthn/blob/master/webauthn/user.go

func (u *userProfile) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.WebauthnID))
	return buf
}

func (u *userProfile) WebAuthnName() string {
	return u.Username
}

func (u *userProfile) WebAuthnDisplayName() string {
	return u.DisplayName
}

// From chrome: apparently this needs to be a secure url
func (u *userProfile) WebAuthnIcon() string {
	return ""
}

// This function is needed to create a unified view of all webauthn credentials
func (u *userProfile) WebAuthnCredentials() []webauthn.Credential {
	logger.Debugf(3, "top of profile.WebAuthnCredentials %+v ", u)
	var rvalue []webauthn.Credential
	for _, authData := range u.WebauthnData {
		if !authData.Enabled {
			continue
		}
		rvalue = append(rvalue, authData.Credential)
	}
	logger.Debugf(3, "profile.WebAuthnCredentials after webauthn.Credential loop")
	for _, u2fAuthData := range u.U2fAuthData {
		logger.Debugf(3, "WebAuthnCredentials: inside u.U2fAuthData")
		if !u2fAuthData.Enabled {
			logger.Debugf(3, "WebAuthnCredentials: skipping disabled u2f credential")
			continue
		}
		/*
			               // A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
				        ID []byte
				        // The public key portion of a Relying Party-specific credential key pair, generated by an authenticator and returned to
				        // a Relying Party at registration time (see also public key credential). The private key portion of the credential key
				        // pair is known as the credential private key. Note that in the case of self attestation, the credential key pair is also
				        // used as the attestation key pair, see self attestation for details.
				        PublicKey []byte
				        // The attestation format used (if any) by the authenticator when creating the credential.
				        AttestationType string
				        // The Authenticator information for a given certificate
				        Authenticator Authenticator
		*/
		pubKeyBytes := elliptic.Marshal(u2fAuthData.Registration.PubKey.Curve, u2fAuthData.Registration.PubKey.X, u2fAuthData.Registration.PubKey.Y)
		credential := webauthn.Credential{
			AttestationType: "fido-u2f",
			ID:              u2fAuthData.Registration.KeyHandle,
			PublicKey:       pubKeyBytes,
			Authenticator: webauthn.Authenticator{
				// The AAGUID of the authenticator. An AAGUID is defined as an array containing the globally unique
				// identifier of the authenticator model being sought.
				AAGUID:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				SignCount: u2fAuthData.Counter,
			},
		}
		logger.Debugf(2, "WebAuthnCredentials: Added u2f Credential")
		rvalue = append(rvalue, credential)

	}
	logger.Debugf(3, "profile.WebAuthnCredentials done")

	return rvalue
}

// This function will eventualy also do migration of credential data if needed
func (u *userProfile) FixupCredential(username string, displayname string) {
	logger.Debugf(3, "top of profile.FixupCredential ")
	if u.DisplayName == "" {
		u.DisplayName = displayname
	}
	// Check for nil....
	if u.WebauthnID == 0 {
		buf := make([]byte, 8)
		rand.Read(buf)
		u.WebauthnID = binary.LittleEndian.Uint64(buf)
	}
	if u.Username == "" {
		u.Username = displayname
	}
	if u.WebauthnData == nil {
		u.WebauthnData = make(map[int64]*webauthAuthData)
	}
	if u.U2fAuthData == nil {
		u.U2fAuthData = make(map[int64]*u2fAuthData)
	}
}

// next are not actually from there... but make it simpler
func (u *userProfile) AddWebAuthnCredential(cred webauthn.Credential) error {
	index := time.Now().Unix()
	authData := webauthAuthData{
		CreatedAt:  time.Now(),
		Enabled:    true,
		Credential: cred,
	}
	u.WebauthnData[index] = &authData
	return nil
}
