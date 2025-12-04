package main

import (
	"fmt"
	"net/http"
	"time"
)

// CreateChallengeHandler is just a wrapper against the library create challenge handler
func (s *RuntimeState) CreateChallengeHandler(w http.ResponseWriter, r *http.Request) {
	err := s.websshauthenticator.CreateChallengeHandler(w, r)
	if err != nil {
		s.logger.Printf("CreateChallengeHandler error generating challenge err: %s", err)
		s.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
}

// LoginWithChallengeHandler authenticates the user and creates an authcookie
// in this case the authcooke is marked with a maxCertAge bound by the incoming certificate
// expiration
func (s *RuntimeState) LoginWithChallengeHandler(w http.ResponseWriter, r *http.Request) {
	authUser, authMaxAge, userErrString, err := s.websshauthenticator.LoginWithChallenge(r)
	if err != nil {
		s.logger.Printf("error=%s", err)
		errorCode := http.StatusBadRequest
		if userErrString == "" {
			errorCode = http.StatusInternalServerError
		}
		s.writeFailureResponse(w, r, errorCode, userErrString)
		return
	}
	// Ensure even a brokenMaxAge is bound to be the maximum cert lifetime
	maxAge := authMaxAge
	if authMaxAge.After(time.Now().Add(maxCertificateLifetime)) {
		maxAge = time.Now().Add(maxCertificateLifetime)
	}
	cookieVal, err := s.genNewSerializedAuthJWTWithCertNotAfter(authUser, AuthTypeSSHCert,
		int64(maxCertificateLifetime.Seconds()), maxAge)
	if err != nil {
		s.logger.Printf("error=%s", err)
		s.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	_, err = s.withCookieSetNewAuthCookie(w, cookieVal, maxAge)
	if err != nil {
		s.logger.Printf("error=%s", err)
		s.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	//send OK
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")

	s.logger.Debugf(1, "webauth Success for user %s", authUser)
}
