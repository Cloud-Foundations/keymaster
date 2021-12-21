package main

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/duo-labs/webauthn/webauthn"
	"time"
)

// This is the implementation of duo-labs' webauthn User interface
// https://github.com/duo-labs/webauthn/blob/master/webauthn/user.go

func (u *userProfile) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.WebauthnID))
	return buf
	//return nil
}

func (u *userProfile) WebAuthnName() string {
	return u.Username
}

func (u *userProfile) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *userProfile) WebAuthnIcon() string {
	return "Not implemented"
}
func (u *userProfile) WebAuthnCredentials() []webauthn.Credential {
	var rvalue []webauthn.Credential
	for _, authData := range u.WebauthnData {
		rvalue = append(rvalue, authData.Credential)
	}
	return rvalue
}

// This function will eventualy also do migration of credential data if needed
func (u *userProfile) FixupCredential(username string, displayname string) {
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
		u.WebauthnData = make(map[int64]webauthAuthData)
	}
}

/// next are not actually from there... but make it simpler
func (u *userProfile) AddWebAuthnCredential(cred webauthn.Credential) error {
	index := time.Now().Unix()
	authData := webauthAuthData{
		CreatedAt:  time.Now(),
		Enabled:    true,
		Credential: cred,
	}
	u.WebauthnData[index] = authData
	return nil
}
