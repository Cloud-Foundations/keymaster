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
	"runtime"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
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

func checkU2FDevices(logger log.Logger) {
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

}

func doU2FAuthenticate(
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {
	logger.Printf("top of doU2fAuthenticate")
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
	logger.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x",
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

func authenticateHelper(req *u2fhost.AuthenticateRequest, devices []*u2fhost.HidDevice, logger log.DebugLogger) *u2fhost.AuthenticateResponse {
	logger.Debugf(1, "Authenticating with request %+v", req)
	openDevices := []u2fhost.Device{}
	for i, device := range devices {
		err := device.Open()
		if err == nil {
			openDevices = append(openDevices, u2fhost.Device(devices[i]))
			defer func(i int) {
				devices[i].Close()
			}(i)
			version, err := device.Version()
			if err != nil {
				logger.Debugf(1, "Device version error: %s", err.Error())
			} else {
				logger.Debugf(1, "Device version: %s", version)
			}
		}
	}
	if len(openDevices) == 0 {
		logger.Fatalf("Failed to find any devices")
	}
	prompted := false
	timeout := time.After(time.Second * 25)

	interval := time.NewTicker(time.Millisecond * 250)
	defer interval.Stop()
	for {
		select {
		case <-timeout:
			fmt.Println("Failed to get authentication response after 25 seconds")
			return nil
		case <-interval.C:
			for _, device := range openDevices {
				response, err := device.Authenticate(req)
				if err == nil {
					logger.Debugf(1, "device.Authenticate retured non error %s", err)
					return response
				} else if _, ok := err.(u2fhost.TestOfUserPresenceRequiredError); ok && !prompted {
					logger.Printf("\nTouch the flashing U2F device to authenticate...")
					prompted = true
				} else {
					logger.Debugf(1, "Got status response %s", err)
				}
			}
		}
	}
	return nil
}

func withDevicesDoU2FAuthenticate(
	devices []*u2fhost.HidDevice,
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {

	logger.Printf("top of withDevicesDoU2fAuthenticate")
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
	/*
	 */
	req := u2fhost.AuthenticateRequest{
		Challenge: webSignRequest.Challenge,
		AppId:     webSignRequest.AppID,                       // Provided by client or server
		Facet:     webSignRequest.AppID,                       //TODO: FIX this is actually Provided by client, so extract from baseURL
		KeyHandle: webSignRequest.RegisteredKeys[0].KeyHandle, // TODO we should actually iterate over this?
	}
	deviceResponse := authenticateHelper(&req, devices, logger)
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

	logger.Printf("top of withDevicesDoWebAutnfAuthenticate")
	url := baseURL + "/webauthn/AuthBegin/" // TODO: this should be grabbed from the webauthn definition as a const
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
	var credentialAssertion protocol.CredentialAssertion
	err = json.NewDecoder(signRequestResp.Body).Decode(&credentialAssertion)
	if err != nil {
		logger.Fatal(err)
	}
	io.Copy(ioutil.Discard, signRequestResp.Body)
	signRequestResp.Body.Close()

	logger.Debugf(1, "credential Assertion=%+v", credentialAssertion)

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

	//keyHandle := base64.RawURLEncoding.EncodeToString(credentialAssertion.Response.AllowedCredentials[0].CredentialID)

	//
	req := u2fhost.AuthenticateRequest{
		Challenge: credentialAssertion.Response.Challenge.String(),
		/*
		   AppId:     webSignRequest.AppID,                       // Provided by client or server
		   Facet:     webSignRequest.AppID,                       //TODO: FIX this is actually Provided by client, so extract from baseURL
		   KeyHandle: webSignRequest.RegisteredKeys[0].KeyHandle, // TODO we should actually iterate over this?
		*/
		//AppId: appId,
		Facet: appId,
		AppId: credentialAssertion.Response.RelyingPartyID,
		//Facet: credentialAssertion.Response.RelyingPartyID,

		KeyHandle: base64.RawURLEncoding.EncodeToString(credentialAssertion.Response.AllowedCredentials[0].CredentialID),
		WebAuthn:  true,
	}

	deviceResponse := authenticateHelper(&req, devices, logger)
	if deviceResponse == nil {
		logger.Fatal("nil response from device?")
	}
	logger.Debugf(1, "signResponse  authenticateHelper done")

	signature := deviceResponse.SignatureData
	decodedSignature, err := base64.StdEncoding.DecodeString(
		deviceResponse.SignatureData)
	if err == nil {
		signature = base64.RawURLEncoding.EncodeToString(decodedSignature)
	}
	authenticatorData := deviceResponse.AuthenticatorData
	decodedAuthenticatorData, err := base64.StdEncoding.DecodeString(deviceResponse.AuthenticatorData)
	if err == nil {
		authenticatorData = base64.RawURLEncoding.EncodeToString(decodedAuthenticatorData)
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
	/*
		authenticatorResponse := protocol.AuthenticatorAssertionResponse{
			Signature: []byte(deviceResponse.SignatureData),
		}
	*/
	// NEXT is broken
	// Now we write the output data:
	responseBytes, err := json.Marshal(webResponse)
	if err != nil {
		logger.Fatal(err)
	}
	/*
		webSignRequestBuf := &bytes.Buffer{}
		err = json.NewEncoder(webSignRequestBuf).Encode(webResponse)
		if err != nil {
			logger.Fatal(err)
		}
	*/
	logger.Debugf(1, "responseBytes=%s", string(responseBytes))
	webSignRequestBuf := bytes.NewReader(responseBytes)

	url = baseURL + "/webauthn/AuthFinish/"
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

	//return fmt.Errorf("not implemented")
}
