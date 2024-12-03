package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/util"
)

//const svcPrefixList= string ["svc-","role-"]

const getRoleRequestingPath = "/v1/getRoleRequestingCert"
const maxRoleRequestingCertDuration = time.Hour * 24 * 45

type roleRequestingCertGenParams struct {
	Role               string
	Duration           time.Duration
	RequestorNetblocks []net.IPNet
	UserPub            interface{}
}

func (state *RuntimeState) parseRoleCertGenParams(r *http.Request) (*roleRequestingCertGenParams, error, error) {
	logger.Debugf(3, "Got client POST connection")
	err := r.ParseMultipartForm(1e7)
	if err != nil {
		state.logger.Println(err)
		return nil, err, nil
	}
	var rvalue roleRequestingCertGenParams
	/*
		Role name: role
		Public Key (PEM): pubkey
		Requestor (Hypervisor) netblock: requestor_netblock
		Target (VM) netblock: target_netblock
		Optional duration: duration (i.e. 730h: :golang: time format)
	*/
	// Role
	roleName := r.Form.Get("role")
	if roleName == "" {
		return nil, fmt.Errorf("Missing role parameter"), nil
	}
	ok, err := state.isAutomationUser(roleName)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, fmt.Errorf("requested role is not automation user"), nil
		//return "", time.Time{}, fmt.Errorf("Bad username  for ip restricted cert"), nil
	}
	rvalue.Role = roleName

	//Duration
	rvalue.Duration = maxRoleRequestingCertDuration

	//RequestorNetblocks
	requestorNetblockStrings, ok := r.Form["requestor_netblock"]
	if !ok {
		return nil, fmt.Errorf("missing required requestor_netblock param"), nil
	}
	for _, netBlock := range requestorNetblockStrings {
		_, parsedNetBlock, err := net.ParseCIDR(netBlock)
		if err != nil {
			state.logger.Printf("%s", err)
			return nil, fmt.Errorf("invalid netblock"), nil
		}
		rvalue.RequestorNetblocks = append(rvalue.RequestorNetblocks, *parsedNetBlock)
	}
	//TargetNetblocks
	targetNetblockStrings, ok := r.Form["target_netblock"]
	if !ok {
		return nil, fmt.Errorf("missing required requestor_netblock param"), nil
	}
	for _, netBlock := range targetNetblockStrings {
		_, _, err := net.ParseCIDR(netBlock)
		if err != nil {
			state.logger.Printf("%s", err)
			return nil, fmt.Errorf("invalid netblock %s", netBlock), nil
		}
		//rvalue.RequestorNetblocks = append(rvalue.RequestorNetblocks, *parsedNetBlock)
	}

	// publickey
	b64pubkey := r.Form.Get("pubkey")
	if b64pubkey == "" {
		return nil, fmt.Errorf("Missing pubkey parameter"), nil
	}
	pkixDerPub, err := base64.URLEncoding.DecodeString(b64pubkey)
	if err != nil {
		state.logger.Printf("%s", err)
		return nil, fmt.Errorf("Invalid encoding for pubkey"), nil
	}
	userPub, err := x509.ParsePKIXPublicKey(pkixDerPub)
	if err != nil {
		state.logger.Printf("%s", err)
		return nil, fmt.Errorf("pubkey is not valid PKIX public key"), nil
	}
	validKey, err := certgen.ValidatePublicKeyStrength(userPub)
	if err != nil {
		return nil, nil, err
	}
	if !validKey {
		return nil, fmt.Errorf("Invalid File, Check Key strength/key type"), nil
	}
	rvalue.UserPub = userPub

	return &rvalue, nil, nil
}

func (state *RuntimeState) isAutomationAdmin(user string) bool {
	isAdmin := state.IsAdminUser(user)
	if isAdmin {
		return true
	}
	for _, adminUser := range state.Config.Base.AutomationAdmins {
		if user == adminUser {
			return true
		}
	}
	return false

}

func (state *RuntimeState) roleRequetingCertGenHandler(w http.ResponseWriter, r *http.Request) {
	var signerIsNull bool
	//var keySigner crypto.Signer

	// copy runtime singer if not nil
	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	/*
		if !signerIsNull {
			keySigner = state.Signer
		}
	*/
	state.Mutex.Unlock()

	//local sanity tests
	if signerIsNull {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer not loaded")
		return
	}

	authData, err := state.checkAuth(w, r,
		state.getRequiredWebUIAuthLevel()|AuthTypeKeymasterX509)
	if err != nil {
		state.logger.Debugf(1, "%v", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)

	// TODO: this should be a different check, for now keep it to admin users
	if !state.isAutomationAdmin(authData.Username) {
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"Not an admin user")
		return
	}

	// TODO: maybe add a check to ensure role certs cannot get role certs?
	//

	/// Now we parse the inputs
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	params, userError, err := state.parseRoleCertGenParams(r)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if userError != nil {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			userError.Error())
		return
	}
	message, code, err := state.postAuthRoleRequetingCertGenProcessor(w, r, params)
	if err != nil {
		state.writeFailureResponse(w, r, code, message)
		if code >= 500 {
			state.logger.Printf("Error generating cert", err)
		}
		return
	}

}
func (state *RuntimeState) postAuthRoleRequetingCertGenProcessor(w http.ResponseWriter, r *http.Request, params *roleRequestingCertGenParams) (string, int, error) {
	signer, caCertDer, err := state.getSignerX509CAForPublic(params.UserPub)
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("Error Finding Cert for public key: %s\n data", err)
		//state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		//state.logger.Printf("Error Finding Cert for public key: %s\n data", err)
		//return
	}
	caCert, err := x509.ParseCertificate(caCertDer)
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("Cannot parse CA Der: %s\n data", err)
	}

	derCert, err := certgen.GenIPRestrictedX509Cert(params.Role, params.UserPub,
		caCert, signer, params.RequestorNetblocks, params.Duration, nil, nil)

	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("Cannot Generate x509cert: %s\n", err)
	}
	parsedCert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("Cannot Parse Generated x509cert: %s\n", err)
	}

	eventNotifier.PublishX509(derCert)
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: derCert}))

	// add logging + metrics
	clientIpAddress := util.GetRequestRealIp(r)

	w.Header().Set("Content-Disposition", `attachment; filename="userCert.pem"`)
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", cert)
	state.logger.Printf("Generated x509 role Requesting Certificate for %s (from %s). Serial: %s",
		params.Role, clientIpAddress, parsedCert.SerialNumber.String())

	return "", 200, nil
}
