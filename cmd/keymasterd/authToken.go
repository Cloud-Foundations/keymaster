package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
	"github.com/Cloud-Foundations/keymaster/lib/paths"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func (state *RuntimeState) generateAuthJWT(username string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       state.Signer,
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	issuer := state.idpGetIssuer()
	now := time.Now().Unix()
	authToken := authInfoJWT{
		Issuer:   issuer,
		Subject:  username,
		Audience: []string{issuer},
		Expiration: now + int64(
			state.Config.Base.WebauthTokenForCliLifetime/time.Second),
		NotBefore: now,
		IssuedAt:  now,
		TokenType: "keymaster_token_auth",
	}
	return jwt.Signed(signer).Claims(authToken).CompactSerialize()
}

func (state *RuntimeState) ShowAuthTokenHandler(w http.ResponseWriter,
	r *http.Request) {
	state.logger.Debugln(1, "Entered GetAuthTokenHandler(). URL: %v\n", r.URL)
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	if err := r.ParseForm(); err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"Error parsing form")
		return
	}
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		state.logger.Debugf(1, "%s", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	displayData := authCodePageTemplateData{
		Title:        "Keymaster CLI Token Display",
		AuthUsername: authData.Username,
	}
	token, err := state.generateAuthJWT(authData.Username)
	if err != nil {
		state.logger.Debugf(1, "%s", err)
		displayData.ErrorMessage = "Unable to generate token"
	} else {
		displayData.Token = token
	}
	err = state.htmlTemplate.ExecuteTemplate(w, "authTokenPage", displayData)
	if err != nil {
		logger.Printf("Failed to execute %s", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

func (state *RuntimeState) SendAuthDocumentHandler(w http.ResponseWriter,
	r *http.Request) {
	state.logger.Debugln(1, "Entered SendAuthDocumentHandler()")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	if err := r.ParseForm(); err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"Error parsing form")
		return
	}
	authData, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		state.logger.Debugln(1, err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authData.Username)
	// Fetch form/query data.
	var portNumber, token string
	if val, ok := r.Form["port"]; !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"No CLI port number provided")
		state.logger.Printf("SendAuthDocument without port number")
		return
	} else {
		if len(val) > 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Just one port number allowed")
			state.logger.Printf("SendAuthDocument with multiple port values")
			return
		}
		portNumber = val[0]
	}
	if val, ok := r.Form["token"]; !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"No token provided")
		state.logger.Printf("SendAuthDocument without token")
		return
	} else {
		if len(val) > 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest,
				"Just one token allowed")
			state.logger.Printf("SendAuthDocument with multiple token values")
			return
		}
		token = val[0]
	}
	authInfo, err := state.getAuthInfoFromJWT(token, "keymaster_token_auth")
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Bad token")
		state.logger.Debugln(0, err)
		return
	}
	if authInfo.Username != authData.Username {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "User mismatch")
		state.logger.Debugf(0, "authticated user: %s != token user: %s\n",
			authData.Username, authInfo.Username)
		return
	}
	if time.Until(authInfo.ExpiresAt) < 0 {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Token expired")
		state.logger.Debugln(0, "token expired")
		return
	}
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}
	if authCookie == nil {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"No auth_cookie")
		state.logger.Debugln(0, "no auth_cookie")
		return
	}
	http.Redirect(w, r,
		fmt.Sprintf("http://localhost:%s%s?auth_cookie=%s",
			portNumber, paths.ReceiveAuthDocument, authCookie.Value),
		http.StatusPermanentRedirect)
}
