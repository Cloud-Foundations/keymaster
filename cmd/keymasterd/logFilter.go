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

func (h *logFilterType) ServeHTTP(w http.ResponseWriter,
	req *http.Request) {
	if strings.HasPrefix(req.URL.Path, "/logs") && !h.publicLogs {
		if h.state.sendFailureToClientIfNonAdmin(w, req) == "" {
			return
		}
	}
	h.handler.ServeHTTP(w, req)
}
