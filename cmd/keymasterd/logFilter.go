package main

import (
	"net/http"
	"strings"
)

type checkAdminUserFunc func(string) bool

type logFilterType struct {
	handler    http.Handler
	publicLogs bool
	state      *RuntimeState
}

func NewLogFilterHandler(handler http.Handler, disableFilter bool,
	state *RuntimeState) http.Handler {
	return &logFilterType{
		handler:    handler,
		publicLogs: disableFilter,
		state:      state,
	}
}

// Returns true if an error was sent, else false indicating admin user or admin
// CA.
func (state *RuntimeState) sendFailureToClientIfNotAdminUserOrCA(
	w http.ResponseWriter, r *http.Request) bool {
	if r.TLS == nil {
		http.Error(w, "TLS mandatory", http.StatusUnauthorized)
		return true
	}
	logger.Debugf(4, "request is TLS %+v", r.TLS)
	if len(r.TLS.VerifiedChains) > 0 {
		logger.Debugf(4, "%+v", r.TLS.VerifiedChains[0][0].Subject)
		username, err := state.getUsernameIfKeymasterSigned(
			r.TLS.VerifiedChains)
		if err != nil {
			state.logger.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		if username != "" && !state.IsAdminUser(username) {
			http.Error(w, "Not admin user", http.StatusUnauthorized)
			return true
		}
		return false
	}
	_, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		return true
	}
	return false
}

func (h *logFilterType) ServeHTTP(w http.ResponseWriter,
	req *http.Request) {
	if strings.HasPrefix(req.URL.Path, "/logs") && !h.publicLogs {
		if h.state.sendFailureToClientIfNotAdminUserOrCA(w, req) {
			return
		}
	}
	h.handler.ServeHTTP(w, req)
}
