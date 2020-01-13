package u2f

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/log"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
	"github.com/tstranex/u2f"
)

const clientDataAuthenticationTypeValue = "navigator.id.getAssertion"

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
	if err := json.NewDecoder(signRequestResp.Body).Decode(&webSignRequest); err != nil {
		//http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		//        return
		logger.Fatal(err)
	}
	io.Copy(ioutil.Discard, signRequestResp.Body)
	signRequestResp.Body.Close()

	// TODO: move this to initialization code, ans pass the device list to this function?
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
	logger.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x", d.Manufacturer, d.Product, d.ProductID, d.VendorID)

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

	///////
	tokenAuthenticationClientData := u2f.ClientData{Typ: clientDataAuthenticationTypeValue, Challenge: webSignRequest.Challenge, Origin: webSignRequest.AppID}
	tokenAuthenticationBuf := new(bytes.Buffer)
	err = json.NewEncoder(tokenAuthenticationBuf).Encode(tokenAuthenticationClientData)
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
		decodedHandle, err := base64.RawURLEncoding.DecodeString(registeredKey.KeyHandle)
		if err != nil {
			logger.Fatal(err)
		}
		keyHandle = decodedHandle

		req = u2ftoken.AuthenticateRequest{
			Challenge:   challenge,
			Application: app,
			KeyHandle:   keyHandle,
		}

		//logger.Printf("%+v", req)
		if err := t.CheckAuthenticate(req); err == nil {
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
	var rawBytes []byte
	for {
		res, err := t.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			logger.Fatal(err)
		}
		rawBytes = res.RawResponse
		logger.Printf("counter = %d, signature = %x", res.Counter, res.Signature)
		break
	}

	// now we do the last request
	var signRequestResponse u2f.SignResponse
	signRequestResponse.KeyHandle = base64.RawURLEncoding.EncodeToString(keyHandle)
	signRequestResponse.SignatureData = base64.RawURLEncoding.EncodeToString(rawBytes)
	signRequestResponse.ClientData = base64.RawURLEncoding.EncodeToString(tokenAuthenticationBuf.Bytes())

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
		logger.Printf("got error from call %s, url='%s'\n", signRequestResp2.Status, url)
		return err
	}
	io.Copy(ioutil.Discard, signRequestResp2.Body)
	return nil
}
