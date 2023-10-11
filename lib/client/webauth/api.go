package webauth

import (
	"net/http"
	"strings"

	"github.com/Cloud-Foundations/golib/pkg/log"
)

type state struct {
	// Parameters.
	userName        string
	webauthBrowser  []string
	tokenFilename   string
	targetUrls      []string
	client          *http.Client
	userAgentString string
	logger          log.DebugLogger
	// Runtime data.
	gotCookie    chan<- struct{}
	portNumber   string
	tokenToWrite []byte
}

// Authenticate will prompt the user to authenticate to a Keymaster server using
// a Web browser, for the specified username.
// The user will occasionally be prompted to copy-paste a token from the Web
// browser, which will be written to the file specified by tokenFilename.
// The authentication cookie will be saved in the client cookie jar which may be
// used for subsequent requests to sign identity certificates.
func Authenticate(userName, webauthBrowser, tokenFilename string,
	targetUrls []string, client *http.Client, userAgentString string,
	logger log.DebugLogger) (string, error) {
	return authenticate(state{
		userName:        userName,
		webauthBrowser:  strings.Fields(webauthBrowser),
		tokenFilename:   tokenFilename,
		targetUrls:      targetUrls,
		client:          client,
		userAgentString: userAgentString,
		logger:          logger,
	})
}
