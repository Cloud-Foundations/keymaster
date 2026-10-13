package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"
	"github.com/tstranex/u2f"
)

/*
This file was 99% create by Claude (Opus 5.5) after being asked
To build tests for serializaiton/deserialization of the profile

as we start the comple removal of u2f this file will need to be
addressed.

*/

// makeTestU2fRegistration builds a u2f registration from raw registration
// data, the same way it is decoded when a profile is deserialized.
func makeTestU2fRegistration(t *testing.T) *u2f.Registration {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test U2F Attestation"},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&privKey.PublicKey, privKey)
	require.NoError(t, err)
	hash := sha256.Sum256([]byte("signed registration data"))
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	require.NoError(t, err)

	keyHandle := []byte{0x0a, 0x0b, 0x0c, 0x0d}
	raw := []byte{0x05}
	raw = append(raw, elliptic.Marshal(elliptic.P256(),
		privKey.PublicKey.X, privKey.PublicKey.Y)...)
	raw = append(raw, byte(len(keyHandle)))
	raw = append(raw, keyHandle...)
	raw = append(raw, certDER...)
	raw = append(raw, signature...)

	var registration u2f.Registration
	require.NoError(t, registration.UnmarshalBinary(raw))
	return &registration
}

// makeTestFullProfile returns a profile with all the 2FA data types populated.
// Times are in UTC and without a monotonic reading so they compare equal
// after a round trip.
func makeTestFullProfile(t *testing.T) *userProfile {
	createdAt := time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC)
	pendingSecret := [][]byte{[]byte("pending-secret-1"), []byte("pending-secret-2")}
	return &userProfile{
		U2fAuthData: map[int64]*u2fAuthData{
			1: {
				Enabled:      true,
				CreatedAt:    createdAt,
				CreatorAddr:  "192.0.2.1",
				Counter:      42,
				Name:         "u2f-key",
				Registration: makeTestU2fRegistration(t),
			},
		},
		RegistrationChallenge: &u2f.Challenge{
			Challenge:     []byte("registration-challenge"),
			Timestamp:     createdAt,
			AppID:         "https://keymaster.example.com",
			TrustedFacets: []string{"https://keymaster.example.com"},
		},
		PendingTOTPSecret:          &pendingSecret,
		LastSuccessfullTOTPCounter: 123456,
		TOTPAuthData: map[int64]*totpAuthData{
			2: {
				Enabled:         true,
				CreatedAt:       createdAt,
				Name:            "totp-device",
				EncryptedSecret: [][]byte{[]byte("encrypted-totp-secret")},
				TOTPType:        1,
				ValidatorAddr:   "192.0.2.2",
			},
		},
		BootstrapOTP: bootstrapOTPData{
			ExpiresAt:  createdAt.Add(time.Hour),
			Sha512Hash: []byte("bootstrap-otp-hash"),
		},
		UserHasRegistered2ndFactor: true,
		WebauthnData: map[int64]*webauthAuthData{
			3: {
				Enabled:   true,
				CreatedAt: createdAt,
				Name:      "webauthn-key",
				Credential: webauthn.Credential{
					ID:              []byte{0x01, 0x02, 0x03, 0x04},
					PublicKey:       []byte("cose-public-key"),
					AttestationType: "packed",
					Transport: []protocol.AuthenticatorTransport{
						protocol.USB, protocol.NFC},
					Flags: webauthn.CredentialFlags{
						UserPresent:    true,
						UserVerified:   true,
						BackupEligible: true,
						BackupState:    true,
					},
					Authenticator: webauthn.Authenticator{
						AAGUID:       []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
						SignCount:    7,
						CloneWarning: true,
						Attachment:   protocol.CrossPlatform,
					},
					Attestation: webauthn.CredentialAttestation{
						ClientDataJSON:     []byte(`{"type":"webauthn.create"}`),
						ClientDataHash:     []byte("client-data-hash"),
						AuthenticatorData:  []byte("authenticator-data"),
						PublicKeyAlgorithm: -7,
						Object:             []byte("attestation-object"),
					},
				},
			},
			4: {
				Enabled:   false,
				CreatedAt: createdAt,
				Name:      "disabled-webauthn-key",
				Credential: webauthn.Credential{
					ID:        []byte{0x05, 0x06},
					PublicKey: []byte("other-cose-public-key"),
				},
			},
		},
		WebauthnID:  0x0102030405060708,
		DisplayName: "User Name",
		Username:    "username",
	}
}

func TestUserProfileSerializeRoundTrip(t *testing.T) {
	profile := makeTestFullProfile(t)

	profileBytes, err := profile.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, profileBytes)

	loadedProfile, err := DeserializeProfile(profileBytes)
	require.NoError(t, err)
	require.Equal(t, profile, loadedProfile)

	// Serializing again must give a profile equal to the original
	profileBytes2, err := loadedProfile.Serialize()
	require.NoError(t, err)
	loadedProfile2, err := DeserializeProfile(profileBytes2)
	require.NoError(t, err)
	require.Equal(t, profile, loadedProfile2)
}

func TestUserProfileSerializeWebAuthnCredentials(t *testing.T) {
	profile := makeTestFullProfile(t)
	profileBytes, err := profile.Serialize()
	require.NoError(t, err)
	loadedProfile, err := DeserializeProfile(profileBytes)
	require.NoError(t, err)

	// The WebAuthn user interface must be unchanged after a round trip
	require.Equal(t, profile.WebAuthnID(), loadedProfile.WebAuthnID())
	require.Equal(t, profile.WebAuthnName(), loadedProfile.WebAuthnName())
	require.Equal(t, profile.WebAuthnDisplayName(),
		loadedProfile.WebAuthnDisplayName())

	// One enabled webauthn credential plus the one derived from u2f
	credentials := loadedProfile.WebAuthnCredentials()
	require.Len(t, credentials, 2)
	var foundWebauthn, foundU2f bool
	for _, credential := range credentials {
		switch credential.AttestationType {
		case "fido-u2f":
			foundU2f = true
			registration := profile.U2fAuthData[1].Registration
			require.Equal(t, registration.KeyHandle, credential.ID)
			require.Equal(t, elliptic.Marshal(elliptic.P256(),
				registration.PubKey.X, registration.PubKey.Y),
				credential.PublicKey)
			require.Equal(t, uint32(42), credential.Authenticator.SignCount)
		default:
			foundWebauthn = true
			require.Equal(t, profile.WebauthnData[3].Credential, credential)
		}
	}
	require.True(t, foundWebauthn)
	require.True(t, foundU2f)
}

func TestUserProfileSerializeCredentialFlags(t *testing.T) {
	// Flags built from the authenticator data, as the webauthn library does.
	// Only the boolean fields are exported, so those are what is stored.
	flags := webauthn.NewCredentialFlags(protocol.FlagUserPresent |
		protocol.FlagUserVerified | protocol.FlagBackupEligible)
	profile := &userProfile{
		WebauthnData: make(map[int64]*webauthAuthData),
		U2fAuthData:  make(map[int64]*u2fAuthData),
	}
	err := profile.AddWebAuthnCredential(webauthn.Credential{
		ID:        []byte{0x01},
		PublicKey: []byte("cose-public-key"),
		Flags:     flags,
	})
	require.NoError(t, err)

	profileBytes, err := profile.Serialize()
	require.NoError(t, err)
	loadedProfile, err := DeserializeProfile(profileBytes)
	require.NoError(t, err)
	credentials := loadedProfile.WebAuthnCredentials()
	require.Len(t, credentials, 1)
	loadedFlags := credentials[0].Flags
	require.True(t, loadedFlags.UserPresent)
	require.True(t, loadedFlags.UserVerified)
	require.True(t, loadedFlags.BackupEligible)
	require.False(t, loadedFlags.BackupState)
}

func TestDeserializeEmptyProfile(t *testing.T) {
	profileBytes, err := (&userProfile{}).Serialize()
	require.NoError(t, err)
	loadedProfile, err := DeserializeProfile(profileBytes)
	require.NoError(t, err)
	// These maps must always be usable after loading
	require.NotNil(t, loadedProfile.U2fAuthData)
	require.NotNil(t, loadedProfile.TOTPAuthData)
	require.NotNil(t, loadedProfile.WebauthnData)
	require.Empty(t, loadedProfile.U2fAuthData)
	require.Empty(t, loadedProfile.TOTPAuthData)
	require.Empty(t, loadedProfile.WebauthnData)
	require.Empty(t, loadedProfile.WebAuthnCredentials())
	require.Equal(t, uint64(0), loadedProfile.WebauthnID)
	require.Equal(t, "", loadedProfile.Username)
}

func TestDeserializeProfileInvalidData(t *testing.T) {
	validBytes, err := makeTestFullProfile(t).Serialize()
	require.NoError(t, err)
	invalidInputs := map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"garbage":   []byte("this is not a gob encoded profile"),
		"truncated": validBytes[:len(validBytes)/2],
	}
	for name, input := range invalidInputs {
		t.Run(name, func(t *testing.T) {
			profile, err := DeserializeProfile(input)
			require.Error(t, err)
			require.Nil(t, profile)
		})
	}
}

// A profile stored by an older keymaster version must still load and survive
// being saved again with the current serialization.
func TestKnownProfileReserialize(t *testing.T) {
	state, tmpdir, err := newTestingState(t)
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	state.Config.Base.DataDirectory = "testdata/webauth-compat-0.16/"
	err = initDB(state)
	require.NoError(t, err)
	profile, ok, _, err := state.LoadUserProfile("username")
	require.NoError(t, err)
	require.True(t, ok)
	require.NotEmpty(t, profile.WebauthnData)

	profileBytes, err := profile.Serialize()
	require.NoError(t, err)
	loadedProfile, err := DeserializeProfile(profileBytes)
	require.NoError(t, err)
	require.Equal(t, profile, loadedProfile)
	require.Equal(t, profile.WebAuthnCredentials(),
		loadedProfile.WebAuthnCredentials())
	state.dbDone <- struct{}{}
}
