package u2f

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/bearsh/hid"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
	"github.com/marshallbrekka/go-u2fhost"
	"github.com/tstranex/u2f"
)

const clientDataAuthenticationTypeValue = "navigator.id.getAssertion"

type ClientData struct {
	Typ                string      `json:"typ,omitempty"`
	Type               string      `json:"type,omitempty"`
	Challenge          string      `json:"challenge"`
	ChannelIdPublicKey interface{} `json:"cid_pubkey,omitempty"`
	Origin             string      `json:"origin"`
}

/*
"response\":{\"authenticatorData\":\"criNDU5iGlmhNuL84SvhejdiYpVWbtvIehKuVx9kVfcBAAAAJA\",\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiJxODM0dUFjdms4Z1lYSVljWDZ6V0NWSElzWHlzZHAwTVAydThaaWMtOTM0Iiwib3JpZ2luIjoiaHR0cHM6Ly9rZXltYXN0ZXIuc2VjLmNsb3VkLXN1cHBvcnQucHVyZXN0b3JhZ2UuY29tIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9\",\"signature\":\"MEUCIGw6WwBd2UupDnf24Qr9eEdBiYlN5ZHv4RBQScZVXCrrAiEApmRUz-H6Rk0ervDWDeQaoKZ9oITVlw8QwbZDDAdFmng\",\"userHandle\":\"\"}
*/

type AuthenticatorResponse struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

/*
	type WebAuthnAuthenticationResponse struct {
	        \"id\":\"bDtn39BgSSwOscXr3ruEGmegBVEd6yntysf8NiG2I2KDz7-CEiw9mIm1BvlQYfg9g1Rq38IpFwEj8Cxn_9uNlA\",\"rawId\":\"bDtn39BgSSwOscXr3ruEGmegBVEd6yntysf8NiG2I2KDz7-CEiw9mIm1BvlQYfg9g1Rq38IpFwEj8Cxn_9uNlA\",\"type\":\"public-key\",\"response\"
*/
type WebAuthnAuthenticationResponse struct {
	Id       string                `json:"id"`
	RawId    string                `json:"rawId"`
	Type     string                `json:"type"`
	Response AuthenticatorResponse `json:"response"`
}

var u2fHostTestUserPresenceError u2fhost.TestOfUserPresenceRequiredError
var u2fHostBadKeyHandleError u2fhost.BadKeyHandleError

func checkU2FDevices(logger log.DebugLogger) {
	// TODO: move this to initialization code, ans pass the device list to this function?
	// or maybe pass the token?...
	devices, err := u2fhid.Devices()
	if err != nil {
		logger.Fatal(err)
	}
	if len(devices) == 0 {
		logger.Fatal("no U2F tokens found")
	}

	// TODO: transform this into an iteration over all found devices
	for _, d := range devices {
		//d := devices[0]
		logger.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x", d.Manufacturer, d.Product, d.ProductID, d.VendorID)

		dev, err := u2fhid.Open(d)
		if err != nil {
			logger.Fatal(err)
		}
		defer dev.Close()
	}

	// New listing
	hidDevices := hid.Enumerate(0x0, 0x0)
	logger.Printf("hid device len=%d", len(hidDevices))
	for i, device := range hidDevices {
		logger.Debugf(1, "h2fHost hid device[%d]=%+v", i, device)
	}

	devices2 := u2fhost.Devices()
	for _, d2 := range devices2 {
		logger.Printf("%+v", d2)
	}
	if len(devices2) == 0 {
		logger.Fatal("no U2F (u2fHost) tokens found")
	} else {
		logger.Printf("u2fHost %d devices found", len(devices2))
	}

}

func doU2FAuthenticate(
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {
	logger.Debugf(1, "top of doU2fAuthenticate")
	url := baseURL + "/u2f/SignRequest"
	signRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Fatal(err)
	}
	signRequest.Header.Set("User-Agent", userAgentString)
	signRequestResp, err := client.Do(signRequest) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to sign request req %s", err)
		return err
	}
	logger.Debugf(0, "Get url request did not failed %+v", signRequestResp)
	// Dont defer the body response Close ... as we need to close it explicitly
	// in the body of the function so that we can reuse the connection
	if signRequestResp.StatusCode != 200 {
		signRequestResp.Body.Close()
		logger.Printf("got error from call %s, url='%s'\n", signRequestResp.Status, url)
		err = errors.New("failed respose from sign request")
		return err
	}
	var webSignRequest u2f.WebSignRequest
	err = json.NewDecoder(signRequestResp.Body).Decode(&webSignRequest)
	if err != nil {
		logger.Fatal(err)
	}
	io.Copy(ioutil.Discard, signRequestResp.Body)
	signRequestResp.Body.Close()
	// TODO: move this to initialization code, ans pass the device list to this
	// function?
	// or maybe pass the token?...
	devices, err := u2fhid.Devices()
	if err != nil {
		logger.Fatal(err)
		return err
	}
	if len(devices) == 0 {
		err = errors.New("no U2F tokens found")
		logger.Println(err)
		return err
	}
	// TODO: transform this into an iteration over all found devices
	d := devices[0]
	logger.Debugf(0, "manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x",
		d.Manufacturer, d.Product, d.ProductID, d.VendorID)
	dev, err := u2fhid.Open(d)
	if err != nil {
		logger.Fatal(err)
	}
	defer dev.Close()
	t := u2ftoken.NewToken(dev)
	version, err := t.Version()
	if err != nil {
		logger.Fatal(err)
	}
	// TODO: Maybe use Debugf()?
	logger.Println("version:", version)
	tokenAuthenticationClientData := u2f.ClientData{
		Typ:       clientDataAuthenticationTypeValue,
		Challenge: webSignRequest.Challenge,
		Origin:    webSignRequest.AppID,
	}
	tokenAuthenticationBuf := new(bytes.Buffer)
	err = json.NewEncoder(tokenAuthenticationBuf).Encode(
		tokenAuthenticationClientData)
	if err != nil {
		logger.Fatal(err)
	}
	reqSignChallenge := sha256.Sum256(tokenAuthenticationBuf.Bytes())
	// TODO: update creation to silence linter
	challenge := make([]byte, 32)
	app := make([]byte, 32)
	challenge = reqSignChallenge[:]
	reqSingApp := sha256.Sum256([]byte(webSignRequest.AppID))
	app = reqSingApp[:]
	// We find out what key is associated to the currently inserted device.
	keyIsKnown := false
	var req u2ftoken.AuthenticateRequest
	var keyHandle []byte
	for _, registeredKey := range webSignRequest.RegisteredKeys {
		decodedHandle, err := base64.RawURLEncoding.DecodeString(
			registeredKey.KeyHandle)
		if err != nil {
			logger.Fatal(err)
		}
		keyHandle = decodedHandle
		req = u2ftoken.AuthenticateRequest{
			Challenge:   challenge,
			Application: app,
			KeyHandle:   keyHandle,
		}
		logger.Debugf(0, "%+v", req)
		if err := t.CheckAuthenticate(req); err != nil {
			logger.Debugln(1, err)
		} else {
			keyIsKnown = true
			break
		}
	}
	if !keyIsKnown {
		err = errors.New("key is not known")
		return err
	}
	// Now we ask the token to sign/authenticate
	logger.Println("authenticating, provide user presence")
	retryCount := 0
	var rawBytes []byte
	for {
		res, err := t.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			if runtime.GOOS == "darwin" && retryCount < 3 {
				retryCount += 1
				if err.Error() == "hid: general error" || err.Error() == "hid: privilege violation" {
					logger.Printf("retry on darwin general error")
					// There is no t.Close() .. so we dot close and create a new one.
					t = u2ftoken.NewToken(dev)
					continue
				}
				if err.Error() == "u2fhid: received error from device: invalid message sequencing" {
					logger.Printf("Error, message sequencing")
					continue
				}

			}
			logger.Fatal(err)
		}
		rawBytes = res.RawResponse
		logger.Printf("counter = %d, signature = %x",
			res.Counter, res.Signature)
		break
	}
	// now we do the last request
	var signRequestResponse u2f.SignResponse
	signRequestResponse.KeyHandle = base64.RawURLEncoding.EncodeToString(
		keyHandle)
	signRequestResponse.SignatureData = base64.RawURLEncoding.EncodeToString(
		rawBytes)
	signRequestResponse.ClientData = base64.RawURLEncoding.EncodeToString(
		tokenAuthenticationBuf.Bytes())
	//
	webSignRequestBuf := &bytes.Buffer{}
	err = json.NewEncoder(webSignRequestBuf).Encode(signRequestResponse)
	if err != nil {
		logger.Fatal(err)
	}
	url = baseURL + "/u2f/SignResponse"
	webSignRequest2, err := http.NewRequest("POST", url, webSignRequestBuf)
	if err != nil {
		logger.Printf("Failure to make http request")
		return err
	}
	webSignRequest2.Header.Set("User-Agent", userAgentString)
	signRequestResp2, err := client.Do(webSignRequest2) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to sign request req %s", err)
		return err
	}
	defer signRequestResp2.Body.Close()
	if signRequestResp2.StatusCode != 200 {
		logger.Printf("got error from call %s, url='%s'\n",
			signRequestResp2.Status, url)
		return err
	}
	io.Copy(ioutil.Discard, signRequestResp2.Body)
	return nil
}

func checkDeviceAuthSuccess(req *u2fhost.AuthenticateRequest, device u2fhost.Device, logger log.DebugLogger) (bool, error) {
	timeout := time.After(time.Second * 3)

	interval := time.NewTicker(time.Millisecond * 250)
	defer interval.Stop()
	for {
		select {
		case <-timeout:
			fmt.Println("Failed to get authentication response after 3 seconds")
			return false, nil
		case <-interval.C:
			_, err := device.Authenticate(req)
			if err == nil {
				logger.Debugf(1, "device.Authenticate returned non error %s", err)
				return true, nil
			}
			logger.Debugf(2, "Checker before exit Got status response %s", err)
			switch err.Error() {
			case u2fHostTestUserPresenceError.Error():
				return true, nil
			case u2fHostBadKeyHandleError.Error():
				return false, nil

			default:
				logger.Debugf(1, "Got status response %s", err)
			}
		}
	}
}

func authenticateHelper(req *u2fhost.AuthenticateRequest, devices []*u2fhost.HidDevice, keyHandles []string, logger log.DebugLogger) (*u2fhost.AuthenticateResponse, error) {
	logger.Debugf(1, "Authenticating with request %+v", req)
	openDevices := []u2fhost.Device{}
	registeredDevices := make(map[u2fhost.AuthenticateRequest]u2fhost.Device)
	for i, device := range devices {
		err := device.Open()
		if err == nil {
			openDevices = append(openDevices, u2fhost.Device(devices[i]))
			defer func(i int) {
				devices[i].Close()
			}(i)
			// For each opened device we test if the handle is present
			// It should be enough for u2f AND webauthn, but is not
			// so we ned to add some logic for registered u2f devices
			// Notice that each device is just cheked once with webauthn flow
			// as prefered mechanism.
			for _, handle := range keyHandles {
				testReq := u2fhost.AuthenticateRequest{
					CheckOnly: true,
					KeyHandle: handle,
					AppId:     req.AppId,
					Facet:     req.Facet,
					Challenge: req.Challenge,
					WebAuthn:  req.WebAuthn,
				}
				copyReq := testReq
				copyReq.CheckOnly = false
				found, err := checkDeviceAuthSuccess(&testReq, device, logger)
				if err != nil {
					logger.Debugf(2, "authenticateHelper: skipping device due[%s] to error err=%s", handle, err)
					continue
				}
				if !found {
					if req.WebAuthn {
						// Depending how some devices u2f devices we registered we need
						// to sometimes (not clear yet,. TODO) to test the device using
						// strict u2f logic and NO webauthn compatibility
						testReq2 := u2fhost.AuthenticateRequest{
							CheckOnly: true,
							KeyHandle: handle,
							AppId:     req.Facet,
							Facet:     req.Facet,
							Challenge: req.Challenge,
							WebAuthn:  false,
						}
						copyReq := testReq2
						copyReq.CheckOnly = false

						found2, err2 := checkDeviceAuthSuccess(&testReq2, device, logger)
						logger.Debugf(3, "authenticateHelper: Fallback check for %s: %v, %s", handle, found2, err2)
						if found2 == true && err2 == nil {
							logger.Debugf(3, "authenticateHelper: Fallback check success for device[%s]", handle)
							registeredDevices[copyReq] = device
							break
						}
					}

					logger.Debugf(2, "skipping device[%s] due to non error", handle)
					continue
				}
				registeredDevices[copyReq] = device
				break
			}
			version, err := device.Version()
			if err != nil {
				logger.Debugf(2, "Device version error: %s", err.Error())
			} else {
				logger.Debugf(2, "Device version: %s", version)
			}
		}
	}
	logger.Debugf(2, " authenticateHelper: registeredDevices=%+v", registeredDevices)

	// Now we actually try to get users touch for devices that are found on the
	// device list
	if len(openDevices) == 0 {
		return nil, fmt.Errorf("Failed to find any devices")
	}
	if len(registeredDevices) == 0 {
		return nil, fmt.Errorf("No registered devices found")
	}
	prompted := false
	timeout := time.After(time.Second * 25)

	interval := time.NewTicker(time.Millisecond * 250)
	defer interval.Stop()
	for {
		select {
		case <-timeout:
			fmt.Println("Failed to get authentication response after 25 seconds")
			return nil, fmt.Errorf("Authentication timeout")
		case <-interval.C:
			for handleReq, device := range registeredDevices {
				response, err := device.Authenticate(&handleReq)
				if err == nil {
					logger.Debugf(1, "device.Authenticate retured non error %s", err)
					return response, nil
				} else if err.Error() == u2fHostTestUserPresenceError.Error() && !prompted {
					logger.Printf("\nTouch the flashing U2F device to authenticate...")
					prompted = true
				} else {
					logger.Debugf(3, "Got status response %s", err)
				}
			}
		}
	}
	return nil, fmt.Errorf("impossible Error")
}

// This ensures the hostname matches...at this moment we do NOT check port number
// Port number should also be checked but leaving that out for now.
func verifyAppId(baseURLStr string, AppIdStr string) (bool, error) {
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return false, err
	}
	baseURLHost, _, _ := strings.Cut(baseURL.Host, ":")
	if AppIdStr == baseURL.Host || AppIdStr == baseURLHost {
		return true, nil
	}
	// The base ID does not match... so we will now try to parse the appID
	AppId, err := url.Parse(AppIdStr)
	if err != nil {
		return false, err
	}
	appIDHost, _, _ := strings.Cut(AppId.Host, ":")
	if appIDHost == baseURLHost {
		return true, nil
	}
	return false, nil
}

func withDevicesDoU2FAuthenticate(
	devices []*u2fhost.HidDevice,
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {

	logger.Debugf(2, "top of withDevicesDoU2fAuthenticate")
	url := baseURL + "/u2f/SignRequest"
	signRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Fatal(err)
	}
	signRequest.Header.Set("User-Agent", userAgentString)
	signRequestResp, err := client.Do(signRequest) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to sign request req %s", err)
		return err
	}
	logger.Debugf(0, "Get url request did not failed %+v", signRequestResp)
	// Dont defer the body response Close ... as we need to close it explicitly
	// in the body of the function so that we can reuse the connection
	if signRequestResp.StatusCode != 200 {
		signRequestResp.Body.Close()
		logger.Printf("got error from call %s, url='%s'\n", signRequestResp.Status, url)
		err = errors.New("failed respose from sign request")
		return err
	}
	var webSignRequest u2f.WebSignRequest
	err = json.NewDecoder(signRequestResp.Body).Decode(&webSignRequest)
	if err != nil {
		logger.Fatal(err)
	}
	io.Copy(ioutil.Discard, signRequestResp.Body)
	signRequestResp.Body.Close()

	var keyHandles []string
	for _, registeredKey := range webSignRequest.RegisteredKeys {
		keyHandles = append(keyHandles, registeredKey.KeyHandle)
	}

	req := u2fhost.AuthenticateRequest{
		Challenge: webSignRequest.Challenge,
		AppId:     webSignRequest.AppID,                       // Provided by client or server
		Facet:     webSignRequest.AppID,                       //TODO: FIX this is actually Provided by client, so extract from baseURL
		KeyHandle: webSignRequest.RegisteredKeys[0].KeyHandle, // TODO we should actually iterate over this?
	}
	deviceResponse, err := authenticateHelper(&req, devices, keyHandles, logger)
	if err != nil {
		return err
	}
	if deviceResponse == nil {
		logger.Fatal("nil response from device?")
	}
	logger.Debugf(1, "signResponse  authenticateHelper done")

	// Now we write the output data:

	webSignRequestBuf := &bytes.Buffer{}
	err = json.NewEncoder(webSignRequestBuf).Encode(deviceResponse)
	if err != nil {
		logger.Fatal(err)
	}
	url = baseURL + "/u2f/SignResponse"
	webSignRequest2, err := http.NewRequest("POST", url, webSignRequestBuf)
	if err != nil {
		logger.Printf("Failure to make http request")
		return err
	}
	webSignRequest2.Header.Set("User-Agent", userAgentString)
	signRequestResp2, err := client.Do(webSignRequest2) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to sign request req %s", err)
		return err
	}
	defer signRequestResp2.Body.Close()
	logger.Debugf(1, "signResponse request complete")
	if signRequestResp2.StatusCode != 200 {
		logger.Debugf(0, "got error from call %s, url='%s'\n",
			signRequestResp2.Status, url)
		return err
	}
	logger.Debugf(1, "signResponse success")
	io.Copy(ioutil.Discard, signRequestResp2.Body)
	return nil

}

func withDevicesDoWebAuthnAuthenticate(
	devices []*u2fhost.HidDevice,
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {

	logger.Debugf(1, "top of withDevicesDoWebAutnfAuthenticate")
	targetURL := baseURL + "/webauthn/AuthBegin/" // TODO: this should be grabbed from the webauthn definition as a const
	signRequest, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		logger.Fatal(err)
	}
	signRequest.Header.Set("User-Agent", userAgentString)
	signRequestResp, err := client.Do(signRequest) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to sign request req %s", err)
		return err
	}
	logger.Debugf(1, "Get url request did not failed %+v", signRequestResp)
	// Dont defer the body response Close ... as we need to close it explicitly
	// in the body of the function so that we can reuse the connection
	if signRequestResp.StatusCode != 200 {
		signRequestResp.Body.Close()
		logger.Printf("got error from call %s, url='%s'\n", signRequestResp.Status, targetURL)
		return fmt.Errorf("Failed response from remote sign request endpoint remote status=%s", signRequestResp.Status)
	}
	var credentialAssertion protocol.CredentialAssertion
	err = json.NewDecoder(signRequestResp.Body).Decode(&credentialAssertion)
	if err != nil {
		logger.Fatal(err)
	}
	io.Copy(ioutil.Discard, signRequestResp.Body)
	signRequestResp.Body.Close()

	logger.Debugf(2, "credential Assertion=%+v", credentialAssertion)
	appId := credentialAssertion.Response.RelyingPartyID
	if credentialAssertion.Response.Extensions != nil {
		appIdIface, ok := credentialAssertion.Response.Extensions["appid"]
		if ok {
			extensionAppId, ok := appIdIface.(string)
			if ok {
				appId = extensionAppId
			}
		}
	}
	// TODO: add check on length of returned data
	validAppId, err := verifyAppId(baseURL, appId)
	if err != nil {
		return err
	}
	if !validAppId {
		return fmt.Errorf("Invalid AppId(escaped)=%s for base=%s", url.QueryEscape(appId), baseURL)
	}

	var keyHandles []string
	for _, credential := range credentialAssertion.Response.AllowedCredentials {
		keyHandles = append(keyHandles, base64.RawURLEncoding.EncodeToString(credential.CredentialID))
	}
	//keyHandle := base64.RawURLEncoding.EncodeToString(credentialAssertion.Response.AllowedCredentials[0].CredentialID)

	//
	req := u2fhost.AuthenticateRequest{
		Challenge: credentialAssertion.Response.Challenge.String(),
		Facet:     appId,                                       //TODO: FIX this is actually Provided by client, so or at least compere with base url host
		AppId:     credentialAssertion.Response.RelyingPartyID, // Provided by Server
		//AppId: appId,

		KeyHandle: base64.RawURLEncoding.EncodeToString(credentialAssertion.Response.AllowedCredentials[0].CredentialID),
		WebAuthn:  true,
	}

	deviceResponse, err := authenticateHelper(&req, devices, keyHandles, logger)
	if err != nil {
		return err
	}
	if deviceResponse == nil {
		logger.Fatal("nil response from device?")
	}
	logger.Debugf(2, "signResponse  authenticateHelper done")

	signature := deviceResponse.SignatureData
	decodedSignature, err := base64.StdEncoding.DecodeString(
		deviceResponse.SignatureData)
	if err == nil {
		signature = base64.RawURLEncoding.EncodeToString(decodedSignature)
	}
	authenticatorData := deviceResponse.AuthenticatorData
	stringDecodedAuthenticatorData, err := base64.StdEncoding.DecodeString(deviceResponse.AuthenticatorData)
	if err == nil {
		authenticatorData = base64.RawURLEncoding.EncodeToString(stringDecodedAuthenticatorData)
	}
	//
	var clientData ClientData
	clientDataBytes, err := base64.RawURLEncoding.DecodeString(deviceResponse.ClientData)
	if err != nil {
		logger.Fatal("Cant base64 decode ClientData")
	}
	err = json.Unmarshal(clientDataBytes, &clientData)
	if err != nil {
		logger.Fatal("unmarshall clientData")
	}
	logger.Debugf(2, "clientData =%+v", clientData)
	if clientData.Typ == clientDataAuthenticationTypeValue {
		// The device signed data can be with the u2f protocol if compatibility
		// is detected in that case we post on the u2f endpoint
		webSignRequestBuf := &bytes.Buffer{}
		err = json.NewEncoder(webSignRequestBuf).Encode(deviceResponse)
		if err != nil {
			logger.Fatal(err)
		}
		targetURL = baseURL + "/u2f/SignResponse"
		webSignRequest2, err := http.NewRequest("POST", targetURL, webSignRequestBuf)
		if err != nil {
			logger.Printf("Failure to make http request")
			return err
		}
		webSignRequest2.Header.Set("User-Agent", userAgentString)
		signRequestResp2, err := client.Do(webSignRequest2) // Client.Get(targetUrl)
		if err != nil {
			logger.Printf("Failure to sign request req %s", err)
			return err
		}
		defer signRequestResp2.Body.Close()
		logger.Debugf(1, "signResponse request complete")
		if signRequestResp2.StatusCode != 200 {
			logger.Debugf(0, "got error from call %s, url='%s'\n",
				signRequestResp2.Status, targetURL)
			return err
		}
		logger.Debugf(1, "signResponse success")
		io.Copy(ioutil.Discard, signRequestResp2.Body)
		return nil
	}
	webResponse := WebAuthnAuthenticationResponse{
		Id:    deviceResponse.KeyHandle,
		RawId: deviceResponse.KeyHandle,
		Type:  "public-key",
		Response: AuthenticatorResponse{
			AuthenticatorData: authenticatorData,
			ClientDataJSON:    deviceResponse.ClientData,
			Signature:         signature,
		},
	}

	// Now we write the output data:
	responseBytes, err := json.Marshal(webResponse)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Debugf(3, "responseBytes=%s", string(responseBytes))
	webSignRequestBuf := bytes.NewReader(responseBytes)

	targetURL = baseURL + "/webauthn/AuthFinish/"
	webSignRequest2, err := http.NewRequest("POST", targetURL, webSignRequestBuf)
	if err != nil {
		logger.Printf("Failure to make http request")
		return err
	}
	webSignRequest2.Header.Set("User-Agent", userAgentString)
	signRequestResp2, err := client.Do(webSignRequest2) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to sign request req %s", err)
		return err
	}
	defer signRequestResp2.Body.Close()
	logger.Debugf(2, "signResponse request complete")
	if signRequestResp2.StatusCode != 200 {
		logger.Debugf(1, "got error from call %s, url='%s'\n",
			signRequestResp2.Status, targetURL)
		return err
	}
	logger.Debugf(2, "signResponse resp=%+v", signRequestResp2)
	io.Copy(ioutil.Discard, signRequestResp2.Body)
	return nil
}
