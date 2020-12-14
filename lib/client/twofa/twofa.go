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

	"github.com/Cloud-Foundations/Dominator/lib/log"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa/pushtoken"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa/u2f"
	"github.com/Cloud-Foundations/keymaster/lib/client/twofa/totp"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"github.com/flynn/u2f/u2fhid" // client side (interface with hardware)
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

func doCertRequest(client *http.Client, authCookies []*http.Cookie, url, filedata string,
	userAgentString string, logger log.Logger) ([]byte, error) {

	req, err := createKeyBodyRequest("POST", url, filedata)
	if err != nil {
		return nil, err
	}
	// Add the login cookies
	for _, cookie := range authCookies {
		req.AddCookie(cookie)
	}
	req.Header.Set("User-Agent", userAgentString)
	resp, err := client.Do(req) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to do cert request %s", err)
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got error from call %s, url='%s'\n", resp.Status, url)
	}
	return ioutil.ReadAll(resp.Body)

}

func getCertsFromServer(
	signer crypto.Signer,
	userName string,
	password []byte,
	baseUrl string,
	skip2fa bool,
	addGroups bool,
	client *http.Client,
	userAgentString string,
	logger log.DebugLogger) (sshCert []byte, x509Cert []byte, kubernetesCert []byte, err error) {

	loginUrl := baseUrl + proto.LoginPath
	form := url.Values{}
	form.Add("username", userName)
	form.Add("password", string(password[:]))
	req, err := http.NewRequest("POST", loginUrl,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, err
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		logger.Printf("got error from login call %s", loginResp.Status)
		return nil, nil, nil, err
	}
	//Enusre we have at least one cookie
	if len(loginResp.Cookies()) < 1 {
		err = errors.New("No cookies from login")
		return nil, nil, nil, err
	}

	loginJSONResponse := proto.LoginResponse{}
	//body := jsonrr.Result().Body
	err = json.NewDecoder(loginResp.Body).Decode(&loginJSONResponse)
	if err != nil {
		return nil, nil, nil, err
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
			devices, err := u2fhid.Devices()
			if err != nil {
				logger.Fatal(err)
				return nil, nil, nil, err
			}
			if len(devices) > 0 {

				err = u2f.DoU2FAuthenticate(
					client, baseUrl, userAgentString, logger)
				if err != nil {

					return nil, nil, nil, err
				}
				successful2fa = true
			}
		}

		if allowTOTP && !successful2fa {
			err = totp.DoTOTPAuthenticate(
				client, baseUrl, userAgentString, logger)
			if err != nil {

				return nil, nil, nil, err
			}
			successful2fa = true
		}
		if allowVIP && !successful2fa {
			err = pushtoken.DoVIPAuthenticate(
				client, baseUrl, userAgentString, logger)
			if err != nil {

				return nil, nil, nil, err
			}
			successful2fa = true
		}
		// TODO: do better logic when both VIP and OKTA are configured
		if allowOkta2FA && !successful2fa {
			err = pushtoken.DoOktaAuthenticate(
				client, baseUrl, userAgentString, logger)
			if err != nil {
				return nil, nil, nil, err
			}
			successful2fa = true
		}

		if !successful2fa {
			err = errors.New("Failed to Pefrom 2FA (as requested from server)")
			return nil, nil, nil, err
		}

	}

	logger.Debugf(1, "Authentication Phase complete")

	//now get x509 cert
	pubKey := signer.Public()
	derKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, nil, err
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derKey}))

	var urlPostfix string
	if addGroups {
		urlPostfix = "&addGroups=true"
		logger.Debugln(0, "adding \"addGroups\" to request")
	}
	// TODO: urlencode the userName
	x509Cert, err = doCertRequest(
		client,
		loginResp.Cookies(),
		baseUrl+"/certgen/"+userName+"?type=x509"+urlPostfix,
		pemKey,
		userAgentString,
		logger)
	if err != nil {
		return nil, nil, nil, err
	}

	kubernetesCert, err = doCertRequest(
		client,
		loginResp.Cookies(),
		baseUrl+"/certgen/"+userName+"?type=x509-kubernetes",
		pemKey,
		userAgentString,
		logger)
	if err != nil {
		//logger.Printf("Warning: could not get the kubernets cert (old server?) err=%s \n", err)
		kubernetesCert = nil
		//return nil, nil, nil, err
	}

	//// Now we do sshCert!
	// generate and write public key
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, nil, nil, err
	}
	sshAuthFile := string(ssh.MarshalAuthorizedKey(sshPub))
	sshCert, err = doCertRequest(
		client,
		loginResp.Cookies(),
		baseUrl+"/certgen/"+userName+"?type=ssh",
		sshAuthFile,
		userAgentString,
		logger)
	if err != nil {
		return nil, nil, nil, err
	}

	return sshCert, x509Cert, kubernetesCert, nil
}

func getCertFromTargetUrls(
	signer crypto.Signer,
	userName string,
	password []byte,
	targetUrls []string,
	skipu2f bool,
	addGroups bool,
	client *http.Client,
	userAgentString string,
	logger log.DebugLogger) (sshCert []byte, x509Cert []byte, kubernetesCert []byte, err error) {
	success := false

	for _, baseUrl := range targetUrls {
		logger.Printf("attempting to target '%s' for '%s'\n", baseUrl, userName)
		sshCert, x509Cert, kubernetesCert, err = getCertsFromServer(
			signer, userName, password, baseUrl, skipu2f, addGroups,
			client, userAgentString, logger)
		if err != nil {
			logger.Println(err)
			continue
		}
		success = true
		break

	}
	if !success {
		err := errors.New("Failed to get creds")
		return nil, nil, nil, err
	}

	return sshCert, x509Cert, kubernetesCert, nil
}
