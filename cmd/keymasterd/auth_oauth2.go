package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/context"
)

const (
	maxAgeSecondsRedirCookie = 120
	redirCookieName          = "oauth2_redir"
	oauth2LoginBeginPath     = "/auth/oauth2/login"
)

func (state *RuntimeState) oauth2DoRedirectoToProviderHandler(
	w http.ResponseWriter, r *http.Request) {
	if state.Config.Oauth2.Config == nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		logger.Println("asking for oauth2, but it is not defined")
		return
	}
	if !state.Config.Oauth2.Enabled {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Oauth2 is not enabled in for this system")
		logger.Println("asking for oauth2, but it is not enabled")
		return
	}
	cookieVal, err := genRandomString()
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		logger.Println(err)
		return
	}
	// we have to create new context and set redirector...
	expiration := time.Now().Add(time.Duration(maxAgeSecondsRedirCookie) *
		time.Second)
	stateString, err := genRandomString()
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		logger.Println(err)
		return
	}
	cookie := http.Cookie{
		Name:     redirCookieName,
		Value:    cookieVal,
		Expires:  expiration,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	pending := pendingAuth2Request{
		ctx:              context.Background(),
		ExpiresAt:        expiration,
		loginDestination: getLoginDestination(r),
		state:            stateString,
	}
	state.Mutex.Lock()
	state.pendingOauth2[cookieVal] = pending
	state.Mutex.Unlock()
	http.Redirect(w, r, state.Config.Oauth2.Config.AuthCodeURL(stateString),
		http.StatusFound)
}

func httpGet(client *http.Client, url string) ([]byte, error) {
	r, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if r.StatusCode >= 300 {
		return nil, fmt.Errorf(string(body))
	}
	logger.Debugf(8, "HTTP GET %s: %s %s", url, r.Status, string(body))
	return body, nil
}

func (state *RuntimeState) oauth2RedirectPathHandler(w http.ResponseWriter,
	r *http.Request) {
	if state.Config.Oauth2.Config == nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		logger.Println("asking for oauth2, but it is not defined")
		return
	}
	if !state.Config.Oauth2.Enabled {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Oauth2 is not enabled in for this system")
		logger.Println("asking for oauth2, but it is not enabled")
		return
	}
	redirCookie, err := r.Cookie(redirCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Missing setup cookie!")
			logger.Println(err)
			return
		}
		// TODO: this is probably a user error? send back to oath2 login path?
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		logger.Println(err)
		return
	}
	index := redirCookie.Value
	state.Mutex.Lock()
	pending, ok := state.pendingOauth2[index]
	state.Mutex.Unlock()
	if !ok {
		// clear cookie here!!!!
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Invalid setup cookie!")
		logger.Println(err)
		return
	}
	if r.URL.Query().Get("state") != pending.state {
		logger.Printf("state does not match")
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	oauth2Token, err := state.Config.Oauth2.Config.Exchange(pending.ctx,
		r.URL.Query().Get("code"))
	if err != nil {
		logger.Printf("failed to get token: ctx: %+v", pending.ctx)
		http.Error(w, "Failed to exchange token: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	client := state.Config.Oauth2.Config.Client(pending.ctx, oauth2Token)
	body, err := httpGet(client, state.Config.Oauth2.UserinfoUrl)
	if err != nil {
		logger.Printf("fail to fetch %s (%s) ", state.Config.Oauth2.UserinfoUrl,
			err.Error())
		http.Error(w, "Failed to get userinfo from url: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	var data struct {
		Name        string              `json:"name"`
		DisplayName string              `json:"display_name"`
		Login       string              `json:"login"`
		Username    string              `json:"username"`
		Email       string              `json:"email"`
		Attributes  map[string][]string `json:"attributes"`
	}
	logger.Debugf(3, "Userinfo body:'%s'", string(body))
	err = json.Unmarshal(body, &data)
	if err != nil {
		logger.Printf("failed to unmarshall userinfo to fetch %s ", body)
		http.Error(w, "Failed to get unmarshall userinfo: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	// The Name field could also be useful
	logger.Debugf(2, "%+v", data)
	// Check if name is there..
	// TODO: we need a more robust way to get the username and to add some
	// filters. This mechanism is ok for 0.2 but not for 0.3.
	username := data.Login
	if username == "" {
		components := strings.Split(data.Email, "@")
		if len(components[0]) < 1 {
			http.Error(w, "Email from userinfo is invalid: ",
				http.StatusInternalServerError)
			return
		}
		username = strings.ToLower(components[0])
	}
	// Make new auth cookie
	_, err = state.setNewAuthCookie(w, username, AuthTypeFederated)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		logger.Println(err)
		return
	}
	// Delete pending cookie
	state.Mutex.Lock()
	delete(state.pendingOauth2, index)
	state.Mutex.Unlock()
	eventNotifier.PublishWebLoginEvent(username)
	loginDestination := pending.loginDestination
	if loginDestination == "" {
		// Nowhere else to go: go to profile page.
		loginDestination = profilePath
	}
	http.Redirect(w, r, loginDestination, 302)
}
