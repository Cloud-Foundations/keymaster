package main

import (
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestParseRoleCertGenParams(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	//
	state.Config.Base.AutomationUsers = append(state.Config.Base.AutomationUsers, "role1")
	state.Config.Base.AutomationAdmins = append(state.Config.Base.AutomationAdmins, "admin1")

	//first pass everything OK

	userPemBlock, _ := pem.Decode([]byte(testUserPEMPublicKey))
	b64public := base64.RawURLEncoding.EncodeToString(userPemBlock.Bytes)

	form := url.Values{}
	form.Add("identity", "role1")
	form.Add("requestor_netblock", "127.0.0.1/32")
	form.Add("pubkey", b64public)
	form.Add("target_netblock", "192.168.0.174/32")

	//form.Add("password", validPasswordConst)

	req, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	//req.AddCookie(&authCookie)
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, userErr, err := state.parseRoleCertGenParams(req)
	if err != nil {
		t.Fatal(err)
	}
	if userErr != nil {
		t.Fatal(userErr)
	}

}
