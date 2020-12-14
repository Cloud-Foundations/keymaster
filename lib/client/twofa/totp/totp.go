package totp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Cloud-Foundations/Dominator/lib/log"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

func doTOTPAuthenticate(
	client *http.Client,
	baseURL string,
	userAgentString string,
	logger log.DebugLogger) error {
	logger.Printf("top of doTOTPAuthenticate")

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter TOTP code: ")
	totpText, err := reader.ReadString('\n')
	if err != nil {
		logger.Debugf(0, "codeText:  Failure to get string %s", err)
		return err
	}
	totpText = strings.TrimSpace(totpText)
	//fmt.Println(codeText)
	logger.Debugf(1, "codeText:  '%s'", totpText)

	TOTPLoginURL := baseURL + "/api/v0/TOTPAuth"

	form := url.Values{}
	form.Add("OTP", totpText)
	req, err := http.NewRequest("POST", TOTPLoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	req.Header.Set("User-Agent", userAgentString)
	
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
		logger.Printf("got error from login call %s", loginResp.Status)
		return err
	}

	loginJSONResponse := proto.LoginResponse{}
	//body := jsonrr.Result().Body
	err = json.NewDecoder(loginResp.Body).Decode(&loginJSONResponse)
	if err != nil {
		return err
	}
	io.Copy(ioutil.Discard, loginResp.Body)

	logger.Debugf(1, "This the login response=%v\n", loginJSONResponse)

	return nil
}
