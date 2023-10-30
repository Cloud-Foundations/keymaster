package twofa

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa/pushtoken"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa/totp"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa/u2f"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/flynn/u2f/u2fhid" // client side (interface with hardware)
	"github.com/marshallbrekka/go-u2fhost"
	"golang.org/x/crypto/ssh"
)

const clientDataAuthenticationTypeValue = "navigator.id.getAssertion"

// This is now copy-paste from the server test side... probably make public and reuse.
func createKeyBodyRequest(method, urlStr, filedata string) (*http.Request, error) {
	//create attachment....
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	//
	fileWriter, err := bodyWriter.CreateFormFile("pubkeyfile", "somefilename.pub")
	if err != nil {
		fmt.Println("error writing to buffer")
		return nil, err
	}
	// When using a file this used to be: fh, err := os.Open(pubKeyFilename)
	fh := strings.NewReader(filedata)

	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		return nil, err
	}

	err = bodyWriter.WriteField("duration", (*Duration).String())
	if err != nil {
		return nil, err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	req, err := http.NewRequest(method, urlStr, bodyBuf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	return req, nil
}

func doCertRequest(signer crypto.Signer, client *http.Client, userName string,
	baseURL,
	certType string,
	addGroups bool,
	userAgentString string, logger log.DebugLogger) ([]byte, error) {
	pubKey := signer.Public()
	var serializedPubkey string
	switch certType {
	case "x509", "x509-kubernetes":
		derKey, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, err
		}
		serializedPubkey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derKey}))
	case "ssh":
		sshPub, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			return nil, err
		}
		serializedPubkey = string(ssh.MarshalAuthorizedKey(sshPub))
	default:
		return nil, fmt.Errorf("invalid certType requested '%s'", certType)

	}
	var urlPostfix string
	// addgroups only makes sense for x509 plain .. maybe set as a check insetad of dropping?
	if certType == "x509" && addGroups {
		urlPostfix = "&addGroups=true"
		logger.Debugln(0, "adding \"addGroups\" to request")
	}
	requestURL := baseURL + "/certgen/" + userName + "?type=" + certType + urlPostfix
	return doCertRequestInternal(client, requestURL, serializedPubkey, userAgentString, logger)
}

func doCertRequestInternal(client *http.Client,
	targetURL, filedata string,
	userAgentString string, logger log.Logger) ([]byte, error) {

	req, err := createKeyBodyRequest("POST", targetURL, filedata)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgentString)
	resp, err := client.Do(req) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to do cert request %s", err)
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got error from call %s, url='%s'", resp.Status, targetURL)
	}
	return ioutil.ReadAll(resp.Body)
}

// tryFidoMFA performs a fido authentication step
// If there are no devices connected it will return false, nil
// if there are fido devices connected it will return
// true, nil on successul MFA and false, error on failure to
// perform the Fido authentication
func tryFidoMFA(
	baseURL string,
	client *http.Client,
	userAgentString string,
	logger log.DebugLogger,
) (bool, error) {
	// Linux support for the new library is not quite correct
	// so for now we keep using the old library (pure u2f)
	// for linux cli as default. Windows 10 and MacOS have been
	// tested successfully.
	// The env variable allows us to swap what library is used by
	// default
	useWebAuthh := true
	if runtime.GOOS == "linux" {
		useWebAuthh = false
	}
	if os.Getenv("KEYMASTER_USEALTU2FLIB") != "" {
		useWebAuthh = !useWebAuthh
	}
	var err error
	if !useWebAuthh {
		devices, err := u2fhid.Devices()
		if err != nil {
			logger.Printf("could not open hid devices err=%s", err)
			return false, err
		}
		if len(devices) < 1 {
			logger.Debugf(2, "No Fido devices found")
			return false, nil
		}
		err = u2f.DoU2FAuthenticate(
			client, baseURL, userAgentString, logger)
		if err != nil {

			return false, err
		}
		return true, nil
	}
	devices := u2fhost.Devices()
	if devices == nil || len(devices) < 1 {
		logger.Debugf(2, "No Fido devices found")
		return false, nil
	}
	err = u2f.WithDevicesDoWebAuthnAuthenticate(devices,
		client, baseURL, userAgentString, logger)
	if err != nil {
		logger.Printf("Error doing hid webathentication err=%s", err)
		return false, err
	}
	return true, nil
}

// This assumes the http client has a non-nul cookie jar
func authenticateUser(
	userName string,
	password []byte,
	baseURL string,
	skip2fa bool,
	client *http.Client,
	userAgentString string,
	logger log.DebugLogger) (err error) {
	if client == nil {
		return fmt.Errorf("http client is nil")
	}
	loginURL := baseURL + proto.LoginPath
	form := url.Values{}
	form.Add("username", userName)
	form.Add("password", string(password[:]))
	req, err := http.NewRequest("POST", loginURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	req.Header.Set("User-Agent", userAgentString)

	logger.Debugf(1, "About to start login request\n")
	loginResp, err := client.Do(req) //client.Get(targetUrl)
	if err != nil {
		logger.Printf("got error from req")
		logger.Println(err)
		// TODO: differentiate between 400 and 500 errors
		// is OK to fail.. try next
		return err
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		if loginResp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("Unauthorized reponse from server. Check username and/or password")
		}
		logger.Debugf(1, "got error from login call %s", loginResp.Status)
		return fmt.Errorf("got error from login call %s", loginResp.Status)
	}
	//Enusre we have at least one cookie
	if len(loginResp.Cookies()) < 1 {
		err = errors.New("No cookies from login")
		return err
	}

	loginJSONResponse := proto.LoginResponse{}
	//body := jsonrr.Result().Body
	err = json.NewDecoder(loginResp.Body).Decode(&loginJSONResponse)
	if err != nil {
		return err
	}
	io.Copy(ioutil.Discard, loginResp.Body) // We also need to read ALL of the body
	loginResp.Body.Close()                  //so that we can reuse the channel
	logger.Debugf(1, "This the login response=%v\n", loginJSONResponse)

	allowVIP := false
	allowU2F := false
	allowTOTP := false
	allowOkta2FA := false
	for _, backend := range loginJSONResponse.CertAuthBackend {
		if backend == proto.AuthTypePassword {
			skip2fa = true
		}
		if backend == proto.AuthTypeSymantecVIP {
			allowVIP = true
			//remote next statemente later
			//skipu2f = true
		}
		if backend == proto.AuthTypeU2F {
			allowU2F = true
		}
		if backend == proto.AuthTypeTOTP {
			allowTOTP = true
		}
		if backend == proto.AuthTypeOkta2FA {
			allowOkta2FA = true
		}
	}

	// Dont try U2F if chosen by user
	if *noU2F {
		allowU2F = false
	}
	if *noTOTP {
		allowTOTP = false
	}
	if *noVIPAccess {
		allowVIP = false
	}

	// on linux disable U2F is the /sys/class/hidraw is missing
	if runtime.GOOS == "linux" && allowU2F {
		if _, err := os.Stat("/sys/class/hidraw"); os.IsNotExist(err) {
			allowU2F = false
		}

	}
	// upgrade to u2f
	successful2fa := false

	if !skip2fa {
		if allowU2F {
			successful2fa, err = tryFidoMFA(baseURL, client, userAgentString, logger)
			if err != nil {
				return err
			}
		}
		if allowTOTP && !successful2fa {
			err = totp.DoTOTPAuthenticate(
				client, baseURL, userAgentString, logger)
			if err != nil {

				return err
			}
			successful2fa = true
		}
		if allowVIP && !successful2fa {
			err = pushtoken.DoVIPAuthenticate(
				client, baseURL, userAgentString, logger)
			if err != nil {

				return err
			}
			successful2fa = true
		}
		// TODO: do better logic when both VIP and OKTA are configured
		if allowOkta2FA && !successful2fa {
			err = pushtoken.DoOktaAuthenticate(
				client, baseURL, userAgentString, logger)
			if err != nil {
				return err
			}
			successful2fa = true
		}

		if !successful2fa {
			err = errors.New("Failed to Pefrom 2FA (as requested from server)")
			return err
		}

	}
	logger.Debugf(1, "Authentication Phase complete")
	return nil
}

func authenticateToTargetUrls(
	userName string,
	password []byte,
	targetUrls []string,
	skip2fa bool,
	client *http.Client,
	userAgentString string,
	logger log.DebugLogger) (baseURL string, err error) {

	for _, baseURL = range targetUrls {
		logger.Printf("attempting to target '%s' for '%s'\n", baseURL, userName)
		err = authenticateUser(
			userName,
			password,
			baseURL,
			skip2fa,
			client,
			userAgentString,
			logger)
		if err != nil {
			continue
		}
		return baseURL, nil

	}
	return "", fmt.Errorf("Failed to Authenticate to any URL")
}
