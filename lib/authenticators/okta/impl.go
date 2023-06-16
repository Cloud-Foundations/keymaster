package okta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
)

const (
	authPath               = "/api/v1/authn"
	authEndpointFormat     = "https://%s.okta.com" + authPath
	factorsVerifyPathExtra = "/factors/%s/verify"
)

type OktaApiVerifyTOTPFactorDataType struct {
	StateToken string `json:"stateToken,omitempty"`
	PassCode   string `json:"passCode,omitempty"`
}

type OktaApiLoginDataType struct {
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`
}

type OktaApiMFAFactorsType struct {
	Id         string `json:"id,omitempty"`
	FactorType string `json:"factorType,omitempty"`
	Provider   string `json:"provider,omitempty"`
	VendorName string `json:"vendorName,omitempty"`
}

type OktaApiUserProfileType struct {
	Login string `json:"login,omitempty"`
}

type OktaApiUserInfoType struct {
	Id      string                 `json:"id,omitempty"`
	Profile OktaApiUserProfileType `json:"profile,omitempty"`
}

type OktaApiEmbeddedDataResponseType struct {
	User   OktaApiUserInfoType     `json:"user,omitempty"`
	Factor []OktaApiMFAFactorsType `json:"factors,omitempty"`
}

type OktaApiPrimaryResponseType struct {
	StateToken      string                          `json:"stateToken,omitempty"`
	ExpiresAtString string                          `json:"expiresAt,omitempty"`
	Status          string                          `json:"status,omitempty"`
	Embedded        OktaApiEmbeddedDataResponseType `json:"_embedded,omitempty"`
}

type OktaApiPushResponseType struct {
	ExpiresAtString string                          `json:"expiresAt,omitempty"`
	Status          string                          `json:"status,omitempty"`
	FactorResult    string                          `json:"factorResult,omitempty"`
	Embedded        OktaApiEmbeddedDataResponseType `json:"_embedded,omitempty"`
}

func newPublicAuthenticator(oktaDomain string, usernameSuffix string,
	logger log.DebugLogger) (*PasswordAuthenticator, error) {
	return &PasswordAuthenticator{
		authnURL:       fmt.Sprintf(authEndpointFormat, oktaDomain),
		logger:         logger,
		usernameSuffix: usernameSuffix,
		recentAuth:     make(map[string]authCacheData),
	}, nil
}

func (pa *PasswordAuthenticator) passwordAuthenticate(username string,
	password []byte) (bool, error) {
	loginData := OktaApiLoginDataType{
		Password: string(password),
		Username: username + pa.usernameSuffix,
	}
	body := &bytes.Buffer{}
	encoder := json.NewEncoder(body)
	encoder.SetIndent("", "    ") // Make life easier for debugging.
	if err := encoder.Encode(loginData); err != nil {
		return false, err
	}
	req, err := http.NewRequest("POST", pa.authnURL, body)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("bad status: %s", resp.Status)
	}
	decoder := json.NewDecoder(resp.Body)
	var response OktaApiPrimaryResponseType
	if err := decoder.Decode(&response); err != nil {
		return false, err
	}
	pa.logger.Debugf(1, "Okta Authenticator: oktaresponse=%+v", response)
	switch response.Status {
	case "SUCCESS", "MFA_REQUIRED":
		expires, err := time.Parse(time.RFC3339, response.ExpiresAtString)
		if err != nil {
			expires = time.Now().Add(time.Second * 60)
		}
		toCache := authCacheData{response: response, expires: expires}
		pa.mutex.Lock()
		pa.recentAuth[username] = toCache
		pa.mutex.Unlock()
		return true, nil
	default:
		return false, nil
	}
}

func (pa *PasswordAuthenticator) getValidUserResponse(username string) (*OktaApiPrimaryResponseType, error) {
	pa.mutex.Lock()
	userData, ok := pa.recentAuth[username]
	defer pa.mutex.Unlock()
	if !ok {
		return nil, nil
	}
	if userData.expires.Before(time.Now()) {
		delete(pa.recentAuth, username)
		return nil, nil

	}
	return &userData.response, nil
}

func (pa *PasswordAuthenticator) validateUserOTP(username string, otpValue int) (bool, error) {
	userResponse, err := pa.getValidUserResponse(username)
	if err != nil {
		return false, err
	}
	if userResponse == nil {
		return false, nil
	}

	for _, factor := range userResponse.Embedded.Factor {
		if !(factor.FactorType == "token:software:totp" && factor.VendorName == "OKTA") {
			continue
		}
		authURL := fmt.Sprintf(pa.authnURL+factorsVerifyPathExtra, factor.Id)
		verifyStruct := OktaApiVerifyTOTPFactorDataType{
			StateToken: userResponse.StateToken,
			PassCode:   fmt.Sprintf("%06d", otpValue),
		}
		pa.logger.Debugf(2, "AuthURL=%s", authURL)
		pa.logger.Debugf(3, "totpVerifyStruct=%+v", verifyStruct)
		body := &bytes.Buffer{}
		encoder := json.NewEncoder(body)
		encoder.SetIndent("", "    ") // Make life easier for debugging.
		if err := encoder.Encode(verifyStruct); err != nil {
			return false, err
		}
		req, err := http.NewRequest("POST", authURL, body)
		if err != nil {
			return false, err
		}
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("bad status: %s", resp.Status)
		}
		decoder := json.NewDecoder(resp.Body)
		var response OktaApiPrimaryResponseType
		if err := decoder.Decode(&response); err != nil {
			return false, err
		}
		if response.Status != "SUCCESS" {
			continue
		}
		return true, nil
	}

	return false, nil
}

func (pa *PasswordAuthenticator) validateUserPush(username string) (PushResponse, error) {
	userResponse, err := pa.getValidUserResponse(username)
	if err != nil {
		return PushResponseRejected, err
	}
	if userResponse == nil {
		return PushResponseRejected, nil
	}
	rvalue := PushResponseRejected
	for _, factor := range userResponse.Embedded.Factor {
		if !(factor.FactorType == "push" && factor.VendorName == "OKTA") {
			continue
		}
		authURL := fmt.Sprintf(pa.authnURL+factorsVerifyPathExtra, factor.Id)
		verifyStruct := OktaApiVerifyTOTPFactorDataType{
			StateToken: userResponse.StateToken,
		}
		pa.logger.Debugf(2, "AuthURL=%s", authURL)
		pa.logger.Debugf(3, "totpVerifyStruct=%+v", verifyStruct)
		body := &bytes.Buffer{}
		encoder := json.NewEncoder(body)
		encoder.SetIndent("", "    ") // Make life easier for debugging.
		if err := encoder.Encode(verifyStruct); err != nil {
			return PushResponseRejected, err
		}
		req, err := http.NewRequest("POST", authURL, body)
		if err != nil {
			return PushResponseRejected, err
		}
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return PushResponseRejected, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return PushResponseRejected, fmt.Errorf("bad status: %s", resp.Status)
		}
		decoder := json.NewDecoder(resp.Body)
		var response OktaApiPushResponseType
		if err := decoder.Decode(&response); err != nil {
			return PushResponseRejected, err
		}
		switch response.Status {
		case "SUCCESS":
			return PushResponseApproved, nil
		case "MFA_CHALLENGE":
			break
		default:
			pa.logger.Printf("invalid Response status (internal)")
			continue
		}
		//
		switch response.FactorResult {
		case "WAITING":
			rvalue = PushResponseWaiting
			continue
		case "TIMEOUT":
			rvalue = PushResonseTimeout
		default:
			rvalue = PushResponseRejected
		}

	}
	return rvalue, nil
}
