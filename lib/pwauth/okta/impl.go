package okta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Cloud-Foundations/Dominator/lib/log"
)

const (
	authPath           = "/api/v1/authn"
	authEndpointFormat = "https://%s.okta.com" + authPath
)

type loginDataType struct {
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`
}

type responseType struct {
	Status string `json:"status,omitempty"`
}

func newPublicAuthenticator(oktaDomain string, logger log.Logger) (
	*PasswordAuthenticator, error) {
	return &PasswordAuthenticator{
		authnURL: fmt.Sprintf(authEndpointFormat, oktaDomain),
		logger:   logger,
	}, nil
}

func (pa *PasswordAuthenticator) passwordAuthenticate(username string,
	password []byte) (bool, error) {
	loginData := loginDataType{Password: string(password), Username: username}
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
	if resp.StatusCode == http.StatusUnauthorized {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("bad status: %s", resp.Status)
	}
	decoder := json.NewDecoder(resp.Body)
	var response responseType
	if err := decoder.Decode(&response); err != nil {
		return false, err
	}
	switch response.Status {
	case "SUCCESS", "MFA_REQUIRED":
		return true, nil
	default:
		return false, nil
	}
}
