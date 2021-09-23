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
