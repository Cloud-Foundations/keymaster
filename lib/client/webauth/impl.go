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
	"syscall"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/paths"
	"golang.org/x/term"
	"gopkg.in/square/go-jose.v2/jwt"
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
	timer := time.NewTimer(time.Second * 10)
	select {
	case <-gotCookie:
		if !timer.Stop() {
			<-timer.C
		}
		return s.targetUrls[0], nil
	case <-timer.C:
		if !s.happyCookie { // Delete a potentially poison cookie if present.
			os.Remove(s.tokenFilename)
		}
		return "", errors.New("timed out getting cookie")
	}
}

func parseToken(serialisedToken string) (*authInfoJWT, error) {
	token, err := jwt.ParseSigned(serialisedToken)
	if err != nil {
		return nil, err
	}
	var data authInfoJWT
	if err := token.UnsafeClaimsWithoutVerification(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func removeNewline(data []byte) []byte {
	if length := len(data); length < 1 {
		return data
	} else if data[length-1] == '\n' {
		return data[:length-1]
	}
	return data
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
	cmd := exec.Command(s.webauthBrowser[0], s.webauthBrowser[1:]...)
	cmd.Args = append(cmd.Args,
		fmt.Sprintf("%s%s", s.targetUrls[0], paths.ShowAuthToken))
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
		token = string(removeNewline(inputData))
		if _, err := parseToken(token); err != nil {
			s.logger.Printf("Token appears invalid. Try again: %s\n", err)
		} else {
			break
		}
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
	token := string(removeNewline(fileData))
	parsedToken, err := parseToken(token)
	if err != nil {
		return "", err
	}
	if time.Until(time.Unix(parsedToken.Expiration, 0)) < 0 {
		return "", nil
	}
	return token, nil
}

func (s *state) receiveAuthHandler(w http.ResponseWriter, req *http.Request) {
	s.logger.Debugln(1, "started receiveAuthHandler()")
	s.happyCookie = true
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
		fmt.Sprintf("%s%s?port=%s&token=%s",
			s.targetUrls[0], paths.SendAuthDocument, s.portNumber, token))
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

const receiveAuthPageText = `
<html>
  <body>
    <h2>Please close this tab</h2>
  </body>
</html>
`
