package main

import (
	"encoding/json"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/log/debuglogger"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

func handler(w http.ResponseWriter, r *http.Request) {
	logger.Printf("top of generic handller")
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

type oauth2TokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

const testAccessTokenValue = "1234567890"

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	logger.Printf("inside tokenHandler")
	token := oauth2TokenJSON{
		AccessToken:  testAccessTokenValue,
		TokenType:    "Bearer",
		RefreshToken: testAccessTokenValue,
		ExpiresIn:    300,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(token); err != nil {
		logger.Printf("broken stuff")
	}
	//fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

type oauth2claimsTestJSON struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	logger.Printf("isseuserinfo handller")
	userinfo := oauth2claimsTestJSON{
		Sub:   "username@example.com",
		Email: "userbane@example.com",
		Name:  "username",
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userinfo); err != nil {
		logger.Printf("broken stuff")
	}
	//fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func init() {
	//logger = stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger = debuglogger.New(slogger)
	http.HandleFunc("/userinfo", userinfoHandler)
	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/", handler)
	logger.Printf("about to start server")
	go http.ListenAndServe("127.0.0.1:12345", nil)
	time.Sleep(20 * time.Millisecond)
	_, err := http.Get("http://localhost:12345")
	if err != nil {
		logger.Fatal(err)
	}
}

var testOauth2Config = oauth2.Config{
	ClientID:     "foo",
	ClientSecret: "bar",
	Endpoint: oauth2.Endpoint{
		AuthURL:  "http://localhost:12345/auth",
		TokenURL: "http://localhost:12345/token"},
	RedirectURL: "https://example.com" + redirectPath,
	Scopes:      []string{"openidc", "email"},
}

func TestOauth2DoRedirectoToProviderHandlerSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.pendingOauth2 = make(map[string]pendingAuth2Request)

	req, err := http.NewRequest("GET", oauth2LoginBeginPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	// It is now broken because there is no valid oauth2 config
	_, err = checkRequestHandlerCode(req, state.oauth2DoRedirectoToProviderHandler, http.StatusInternalServerError)
	if err != nil {
		t.Fatal(err)
	}

	state.Config.Oauth2.Config = &testOauth2Config
	// Still failure because it it not enabled
	_, err = checkRequestHandlerCode(req, state.oauth2DoRedirectoToProviderHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}

	state.Config.Oauth2.Enabled = true
	//and now we succeed.
	_, err = checkRequestHandlerCode(req, state.oauth2DoRedirectoToProviderHandler, http.StatusFound)
	if err != nil {
		t.Fatal(err)
	}

	// Todo Check for the response contents
}

func TestOauth2RedirectPathHandlerSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.pendingOauth2 = make(map[string]pendingAuth2Request)
	state.Config.Oauth2.UserinfoUrl = "http://localhost:12345/userinfo"

	//initially the request should fail for lack of preconditions
	req, err := http.NewRequest("GET", redirectPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	// oath2 config is invalid
	_, err = checkRequestHandlerCode(req, state.oauth2RedirectPathHandler, http.StatusInternalServerError)
	if err != nil {
		t.Fatal(err)
	}
	state.Config.Oauth2.Config = &testOauth2Config

	// oath2 is not enabled
	_, err = checkRequestHandlerCode(req, state.oauth2RedirectPathHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}
	state.Config.Oauth2.Enabled = true

	// request has no cookies
	_, err = checkRequestHandlerCode(req, state.oauth2RedirectPathHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}
	// has a cookie.. but is not known to the server:
	cookieVal := "supersecret"
	pendingCookie := http.Cookie{Name: redirCookieName, Value: cookieVal}
	req.AddCookie(&pendingCookie)
	// request has no cookies
	_, err = checkRequestHandlerCode(req, state.oauth2RedirectPathHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}

	//Now add the cookie... but no state variable on the query
	expiration := time.Now().Add(time.Duration(maxAgeSecondsRedirCookie) * time.Second)
	expectedState := "somestate"
	state.pendingOauth2[cookieVal] = pendingAuth2Request{
		ExpiresAt: expiration,
		state:     expectedState,
		ctx:       context.Background()}

	_, err = checkRequestHandlerCode(req, state.oauth2RedirectPathHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}
	//TODO: add invalid state
	q := req.URL.Query()
	q.Set("state", "foo")
	q.Set("code", "123")
	req.URL.RawQuery = q.Encode()
	_, err = checkRequestHandlerCode(req, state.oauth2RedirectPathHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}
	//now we add valid state
	q.Set("state", expectedState)
	req.URL.RawQuery = q.Encode()
	_, err = checkRequestHandlerCode(req, state.oauth2RedirectPathHandler, http.StatusFound)
	if err != nil {
		t.Fatal(err)
	}

}
