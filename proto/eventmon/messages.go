package eventmon

const (
	ConnectString = "200 Connected to keymaster eventmon service"
	HttpPath      = "/eventmon/v0"

	AuthTypePassword    = "Password"
	AuthTypeSymantecVIP = "SymantecVIP"
	AuthTypeU2F         = "U2F"
	AuthTypeTOTP        = "TOTP"

	EventTypeAuth                 = "Auth"
	EventTypeServiceProviderLogin = "ServiceProviderLogin"
	EventTypeSSHCert              = "SSHCert"
	EventTypeWebLogin             = "WebLogin"
	EventTypeX509Cert             = "X509Cert"

	VIPAuthTypeOTP  = "VIPAuthOTP"
	VIPAuthTypePush = "VIPAuthPush"
)

// Client sends no data. Server sends a sequence of events.

type EventV0 struct {
	Type string

	// Present for SSH and X509 certificate events.
	CertData []byte `json:",omitempty"`

	AuthType           string `json:",omitempty"` // Present for Auth events.
	ServiceProviderUrl string `json:",omitempty"` // Present for SPLogin events.
	Username           string `json:",omitempty"` // Auth, SPLogin and WebLogin

	VIPAuthType string `json:",omitempty"` // Present for VIP Auth events.
}
