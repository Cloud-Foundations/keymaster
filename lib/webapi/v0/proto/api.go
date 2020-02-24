package proto

const LoginPath = "/api/v0/login"

const (
	AuthTypePassword      = "password"
	AuthTypeFederated     = "federated"
	AuthTypeU2F           = "U2F"
	AuthTypeSymantecVIP   = "SymantecVIP"
	AuthTypeIPCertificate = "IPCertificate"
	AuthTypeTOTP          = "TOTP"
	AuthTypeOkta2FA       = "Okta2FA"
)

type LoginResponse struct {
	Message         string   `json:"message"`
	CertAuthBackend []string `json:"auth_backend"`
}
