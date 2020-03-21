package main

import (
	"net/http"
	"strings"
)

type checkAdminUserFunc func(string) bool

type logFilterType struct {
	checkAdminUser checkAdminUserFunc
	handler        http.Handler
	publicLogs     bool
}

func NewLogFilterHandler(handler http.Handler, disableFilter bool,
	checkAdminUser checkAdminUserFunc) http.Handler {
	return &logFilterType{
		checkAdminUser: checkAdminUser,
		handler:        handler,
		publicLogs:     disableFilter,
	}
}

func getValidAdminRemoteUsername(w http.ResponseWriter, r *http.Request,
	checkAdminUser checkAdminUserFunc) (string, error) {
	if r.TLS != nil {
		logger.Debugf(4, "request is TLS %+v", r.TLS)
		if len(r.TLS.VerifiedChains) > 0 {
			logger.Debugf(4, "%+v", r.TLS.VerifiedChains[0][0].Subject)
			clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
			if clientName != "" && checkAdminUser(clientName) {
				return clientName, nil
			}
		}
	}
	return "", nil
}

func (h *logFilterType) ServeHTTP(w http.ResponseWriter,
	req *http.Request) {
	if strings.HasPrefix(req.URL.Path, "/logs") {
		if !h.publicLogs {
			username, err := getValidAdminRemoteUsername(w, req,
				h.checkAdminUser)
			if err != nil {
				http.Error(w, "Check auth Failed", http.StatusInternalServerError)
				return
			}
			if username == "" {
				http.Error(w, "Invalid/Unknown Authentication", http.StatusUnauthorized)
				return
			}
		}
	}

	h.handler.ServeHTTP(w, req)
}
