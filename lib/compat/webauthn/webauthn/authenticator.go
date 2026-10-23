package webauthn

import (
	//"github.com/go-webauthn/webauthn/protocol"
	"github.com/Cloud-Foundations/keymaster/lib/compat/webauthn/protocol"
)

type Authenticator struct {
	// The AAGUID of the authenticator. An AAGUID is defined as an array containing the globally unique
	// identifier of the authenticator model being sought.
	AAGUID []byte `json:"AAGUID"`

	// SignCount -Upon a new login operation, the Relying Party compares the stored signature counter value
	// with the new signCount value returned in the assertion’s authenticator data. If this new
	// signCount value is less than or equal to the stored value, a cloned authenticator may
	// exist, or the authenticator may be malfunctioning.
	SignCount uint32 `json:"signCount"`

	// CloneWarning - This is a signal that the authenticator may be cloned, i.e. at least two copies of the
	// credential private key may exist and are being used in parallel. Relying Parties should incorporate
	// this information into their risk scoring. Whether the Relying Party updates the stored signature
	// counter value in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.
	CloneWarning bool `json:"cloneWarning"`

	// Attachment is the authenticatorAttachment value returned by the request.
	Attachment protocol.AuthenticatorAttachment `json:"attachment"`
}

// SelectAuthenticator allow for easy marshaling of authenticator options that are provided to the user.
func SelectAuthenticator(att string, rrk *bool, uv string) protocol.AuthenticatorSelection {
	return protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment(att),
		RequireResidentKey:      rrk,
		UserVerification:        protocol.UserVerificationRequirement(uv),
	}
}
