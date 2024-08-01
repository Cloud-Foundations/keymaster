package webauth

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/paths"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/term"
)

const (
	authCookieName      = "auth_cookie"
	pathCloseTabRequest = "/closeTabRequest"
)

type authInfoJWT struct {
	Subject    string `json:"sub,omitempty"`
	Expiration int64  `json:"exp,omitempty"`
}

func authenticate(s state) (string, error) {
	// Fail early if token file cannot be written.
	dirname := filepath.Dir(s.tokenFilename)
	if err := os.MkdirAll(dirname, 0755); err != nil {
		return "", err
	}
	gotCookie := make(chan struct{}, 1)
	s.gotCookie = gotCookie
	if err := s.startLocalServer(); err != nil {
		return "", err
	}
	token, err := s.getToken()
	if err != nil {
		return "", err
	}
	if err := s.startAuthRequest(token); err != nil {
		return "", err
	}
	timer := time.NewTimer(time.Minute)
	select {
	case <-gotCookie:
		if !timer.Stop() {
			<-timer.C
		}
		return s.targetUrls[0], nil
	case <-timer.C:
		return "", errors.New("timed out getting cookie")
	}
}

func parseToken(serialisedToken string) (*authInfoJWT, error) {
	token, err := jwt.ParseSigned(serialisedToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	var data authInfoJWT
	if err := token.UnsafeClaimsWithoutVerification(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func startCommand(cmd *exec.Cmd, timeout time.Duration) error {
	errorChannel := make(chan error, 1)
	timer := time.NewTimer(timeout)
	go func(errorChannel chan<- error) {
		errorChannel <- cmd.Run()
	}(errorChannel)
	select {
	case err := <-errorChannel:
		if !timer.Stop() {
			<-timer.C
		}
		return err
	case <-timer.C:
		return nil
	}
}

func (s *state) closeTabRequestHandler(w http.ResponseWriter,
	req *http.Request) {
	w.Write([]byte(receiveAuthPageText))
}

func (s *state) getToken() (string, error) {
	if token, err := s.readToken(); err != nil {
		s.logger.Println(err)
	} else if token != "" {
		return token, nil
	}
	os.Remove(s.tokenFilename) // Delete a potentially poison cookie if present.
	cmd := exec.Command(s.webauthBrowser[0], s.webauthBrowser[1:]...)
	cmd.Args = append(cmd.Args,
		fmt.Sprintf("%s%s?user=%s", s.targetUrls[0], paths.ShowAuthToken,
			s.userName))
	if err := startCommand(cmd, time.Millisecond*200); err != nil {
		return "", err
	}
	var token string
	var inputData []byte
	for {
		fmt.Printf("Enter token: ")
		var err error
		inputData, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		fmt.Println()
		token = strings.TrimSpace(string(inputData))
		if _, err := parseToken(token); err != nil {
			s.logger.Printf("Token appears invalid. Try again: %s\n", err)
			continue
		}
		if err := s.verifyToken(token); err != nil {
			s.logger.Printf("Unable to verify token. Try again: %s\n", err)
			continue
		}
		break
	}
	s.tokenToWrite = inputData // Write later once fully verified.
	return token, nil
}

func (s *state) readToken() (string, error) {
	fileData, err := ioutil.ReadFile(s.tokenFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	token := strings.TrimSpace(string(fileData))
	parsedToken, err := parseToken(token)
	if err != nil {
		return "", err
	}
	if time.Until(time.Unix(parsedToken.Expiration, 0)) < 0 {
		return "", nil
	}
	if err := s.verifyToken(token); err != nil {
		return "", fmt.Errorf("unable to verify token: %s", err)
	}
	return token, nil
}

func (s *state) receiveAuthHandler(w http.ResponseWriter, req *http.Request) {
	s.logger.Debugln(1, "started receiveAuthHandler()")
	if len(s.tokenToWrite) > 0 { // If we are here, Keymaster liked the token.
		err := ioutil.WriteFile(s.tokenFilename, s.tokenToWrite, 0600)
		if err != nil {
			s.logger.Println(err)
		}
	}
	// Fetch form/query data.
	if err := req.ParseForm(); err != nil {
		s.logger.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error parsing form"))
		return
	}
	var authCookieValue string
	if val, ok := req.Form["auth_cookie"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No auth_cookie"))
		return
	} else {
		if len(val) > 1 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Just one auth_cookie allowed"))
			return
		}
		authCookieValue = val[0]
	}
	authCookie := &http.Cookie{Name: "auth_cookie", Value: authCookieValue}
	for _, targetUrl := range s.targetUrls {
		targetURL, err := url.Parse(targetUrl)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Error parsing URL"))
			s.logger.Println(err)
			return
		}
		s.client.Jar.SetCookies(targetURL, []*http.Cookie{authCookie})
	}
	s.gotCookie <- struct{}{}
	http.Redirect(w, req, pathCloseTabRequest, http.StatusPermanentRedirect)
}

func (s *state) serve(listener net.Listener, serveMux *http.ServeMux) {
	if err := http.Serve(listener, serveMux); err != nil {
		panic(err)
	}
}

func (s *state) startAuthRequest(token string) error {
	cmd := exec.Command(s.webauthBrowser[0], s.webauthBrowser[1:]...)
	cmd.Args = append(cmd.Args,
		fmt.Sprintf("%s%s?port=%s&user=%s&token=%s",
			s.targetUrls[0], paths.SendAuthDocument, s.portNumber, s.userName,
			token))
	return startCommand(cmd, time.Millisecond*200)
}

func (s *state) startLocalServer() error {
	listener, err := net.Listen("tcp", "localhost:")
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return err
	}
	s.logger.Debugf(0, "listening on localhost:%s\n", port)
	s.portNumber = port
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(paths.ReceiveAuthDocument, s.receiveAuthHandler)
	serveMux.HandleFunc(pathCloseTabRequest, s.closeTabRequestHandler)
	go s.serve(listener, serveMux)
	return nil
}

func (s *state) verifyToken(token string) error {
	resp, err := s.client.Get(fmt.Sprintf("%s%s?token=%s",
		s.targetUrls[0], paths.VerifyAuthToken, token))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		s.logger.Println("Token verification not supported")
		return nil
	}
	if body, err := ioutil.ReadAll(resp.Body); err != nil {
		return err
	} else {
		return errors.New(string(body))
	}
}

const receiveAuthPageText = `
<html>
  <body>
    <h2>Please close this tab</h2>
  </body>
</html>
`
