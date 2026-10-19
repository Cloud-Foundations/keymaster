package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"time"

	compatprotocol "github.com/Cloud-Foundations/keymaster/lib/compat/webauthn/protocol"
	compatwebauthn "github.com/Cloud-Foundations/keymaster/lib/compat/webauthn/webauthn"
	"github.com/go-webauthn/webauthn/protocol"
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

// NOTE: The conversion from the compat to old and back was done via
// Claude Code (Opus 5.5). This includes:
// compatFlagsToNew, compatToNewFromAttestation, compatToNew, and newCredToOldCred

// compatFlagsToNew rebuilds the raw authenticator flags from the compat
// credential flags. The raw value of the compat flags is unexported and is
// lost on serialization, so the boolean fields are authoritative.
func compatFlagsToNew(inflags compatwebauthn.CredentialFlags) webauthn.CredentialFlags {
	raw := protocol.AuthenticatorFlags(inflags.ProtocolValue())
	setFlag := func(flag protocol.AuthenticatorFlags, value bool) {
		if value {
			raw |= flag
		} else {
			raw &^= flag
		}
	}
	setFlag(protocol.FlagUserPresent, inflags.UserPresent)
	setFlag(protocol.FlagUserVerified, inflags.UserVerified)
	setFlag(protocol.FlagBackupEligible, inflags.BackupEligible)
	setFlag(protocol.FlagBackupState, inflags.BackupState)
	return webauthn.NewCredentialFlags(raw)
}

// compatToNewFromAttestation re-parses the stored raw attestation and builds
// the credential using webauthn.NewCredential.
func compatToNewFromAttestation(incred compatwebauthn.Credential) (*webauthn.Credential, error) {
	rawResponse := protocol.AuthenticatorAttestationResponse{
		AuthenticatorResponse: protocol.AuthenticatorResponse{
			ClientDataJSON: incred.Attestation.ClientDataJSON,
		},
		AuthenticatorData:  incred.Attestation.AuthenticatorData,
		PublicKey:          incred.PublicKey,
		PublicKeyAlgorithm: incred.Attestation.PublicKeyAlgorithm,
		AttestationObject:  incred.Attestation.Object,
	}
	for _, transport := range incred.Transport {
		rawResponse.Transports = append(rawResponse.Transports, string(transport))
	}
	parsedResponse, err := rawResponse.Parse()
	if err != nil {
		return nil, err
	}
	creationData := protocol.ParsedCredentialCreationData{
		ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
			RawID: incred.ID,
			AuthenticatorAttachment: protocol.AuthenticatorAttachment(
				incred.Authenticator.Attachment),
		},
		Response: *parsedResponse,
		Raw: protocol.CredentialCreationResponse{
			AttestationResponse: rawResponse,
		},
	}
	creationData.ID = base64.RawURLEncoding.EncodeToString(incred.ID)
	creationData.Type = string(protocol.PublicKeyCredentialType)
	cred, err := webauthn.NewCredential(incred.Attestation.ClientDataHash, &creationData)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cred.ID, incred.ID) ||
		!bytes.Equal(cred.PublicKey, incred.PublicKey) {
		return nil, fmt.Errorf("stored attestation does not match credential")
	}
	return cred, nil
}

// compatToNew converts a credential stored with the compat (old library)
// format into a credential of the current go-webauthn library.
// Fields that cannot be recovered from the compat credential:
//   - Extensions: client extension results (credProps.rk, prf, largeBlob,
//     hmacCreateSecret) were never stored. Authenticator extension outputs
//     (credProtect, minPinLength, credBlob, hmac-secret) are only recovered
//     when the raw attestation object is stored.
//   - AttestationType: the compat library stored the attestation *format* in
//     this field. The real attestation type is only recovered when the raw
//     attestation object is stored.
func compatToNew(incred compatwebauthn.Credential) (webauthn.Credential, error) {
	if len(incred.ID) == 0 || len(incred.PublicKey) == 0 {
		return webauthn.Credential{}, fmt.Errorf("credential missing ID or public key")
	}
	var cred webauthn.Credential
	if len(incred.Attestation.Object) > 0 &&
		len(incred.Attestation.ClientDataJSON) > 0 {
		newCred, err := compatToNewFromAttestation(incred)
		if err != nil {
			logger.Debugf(1, "compatToNew: cannot use stored attestation: %s", err)
		} else {
			cred = *newCred
		}
	}
	if cred.ID == nil {
		// No usable attestation: copy field by field.
		cred = webauthn.Credential{
			ID:        incred.ID,
			PublicKey: incred.PublicKey,
			Authenticator: webauthn.Authenticator{
				AAGUID: incred.Authenticator.AAGUID,
			},
			Attestation: webauthn.CredentialAttestation{
				ClientDataJSON:     incred.Attestation.ClientDataJSON,
				ClientDataHash:     incred.Attestation.ClientDataHash,
				AuthenticatorData:  incred.Attestation.AuthenticatorData,
				PublicKeyAlgorithm: incred.Attestation.PublicKeyAlgorithm,
				Object:             incred.Attestation.Object,
			},
		}
		if protocol.IsAttestationFormatString(incred.AttestationType) {
			cred.AttestationFormat = incred.AttestationType
		} else {
			cred.AttestationType = incred.AttestationType
		}
	}
	// The following values change after registration, so the stored values
	// win over the ones derived from the registration attestation.
	cred.Transport = nil
	for _, transport := range incred.Transport {
		cred.Transport = append(cred.Transport,
			protocol.AuthenticatorTransport(transport))
	}
	cred.Flags = compatFlagsToNew(incred.Flags)
	cred.Authenticator.SignCount = incred.Authenticator.SignCount
	cred.Authenticator.CloneWarning = incred.Authenticator.CloneWarning
	cred.Authenticator.Attachment = protocol.AuthenticatorAttachment(
		incred.Authenticator.Attachment)
	return cred, nil
}

// newCredToOldCred converts a credential of the current go-webauthn library
// into the compat (old library) format used for storage.
// Fields that cannot be stored in the compat credential:
//   - Extensions: the compat credential has no place for them.
//   - AttestationType/AttestationFormat: the compat credential has a single
//     field which historically holds the attestation *format*. The format is
//     stored there when known, otherwise the attestation type. The type can
//     be re-derived later from the stored raw attestation.
func newCredToOldCred(incred webauthn.Credential) compatwebauthn.Credential {
	attestationType := incred.AttestationFormat
	if attestationType == "" {
		attestationType = incred.AttestationType
	}
	cred := compatwebauthn.Credential{
		ID:              incred.ID,
		PublicKey:       incred.PublicKey,
		AttestationType: attestationType,
		Flags: compatwebauthn.NewCredentialFlags(
			compatprotocol.AuthenticatorFlags(incred.Flags.ProtocolValue())),
		Authenticator: compatwebauthn.Authenticator{
			AAGUID:       incred.Authenticator.AAGUID,
			SignCount:    incred.Authenticator.SignCount,
			CloneWarning: incred.Authenticator.CloneWarning,
			Attachment: compatprotocol.AuthenticatorAttachment(
				incred.Authenticator.Attachment),
		},
		Attestation: compatwebauthn.CredentialAttestation{
			ClientDataJSON:     incred.Attestation.ClientDataJSON,
			ClientDataHash:     incred.Attestation.ClientDataHash,
			AuthenticatorData:  incred.Attestation.AuthenticatorData,
			PublicKeyAlgorithm: incred.Attestation.PublicKeyAlgorithm,
			Object:             incred.Attestation.Object,
		},
	}
	// The raw flags may be missing if the credential flags were not built
	// with NewCredentialFlags, so the boolean fields are authoritative.
	cred.Flags.UserPresent = incred.Flags.UserPresent
	cred.Flags.UserVerified = incred.Flags.UserVerified
	cred.Flags.BackupEligible = incred.Flags.BackupEligible
	cred.Flags.BackupState = incred.Flags.BackupState
	for _, transport := range incred.Transport {
		cred.Transport = append(cred.Transport,
			compatprotocol.AuthenticatorTransport(transport))
	}
	return cred
}

// This function is needed to create a unified view of all webauthn credentials
func (u *userProfile) WebAuthnCredentials() []webauthn.Credential {
	logger.Debugf(3, "top of profile.WebAuthnCredentials %+v ", u)
	var rvalue []webauthn.Credential
	for _, authData := range u.WebauthnData {
		if !authData.Enabled {
			continue
		}
		converted, err := compatToNew(authData.Credential)
		if err != nil {
			continue
		}
		rvalue = append(rvalue, converted)
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
		Credential: newCredToOldCred(cred),
	}
	u.WebauthnData[index] = &authData
	return nil
}

func (u *userProfile) Serialize() ([]byte, error) {
	var gobBuffer bytes.Buffer
	encoder := gob.NewEncoder(&gobBuffer)
	if err := encoder.Encode(u); err != nil {
		return nil, err
	}
	return gobBuffer.Bytes(), nil
}

func DeserializeProfile(profileBytes []byte) (*userProfile, error) {
	var loadedProfile userProfile
	gobReader := bytes.NewReader(profileBytes)
	decoder := gob.NewDecoder(gobReader)
	err := decoder.Decode(&loadedProfile)
	if err != nil {
		return nil, err
	}
	if loadedProfile.WebauthnData == nil {
		loadedProfile.WebauthnData = make(map[int64]*webauthAuthData)
	}
	if loadedProfile.U2fAuthData == nil {
		loadedProfile.U2fAuthData = make(map[int64]*u2fAuthData)
	}
	if loadedProfile.TOTPAuthData == nil {
		loadedProfile.TOTPAuthData = make(map[int64]*totpAuthData)
	}
	return &loadedProfile, nil
}
