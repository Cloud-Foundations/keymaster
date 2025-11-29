package main

import (
	"fmt"
	"net/http"
	"time"
)

// CreateChallengeHandler is an example of how to write a handler for
// the path to create the challenge
func (s *RuntimeState) CreateChallengeHandler(w http.ResponseWriter, r *http.Request) {
	err := s.websshauthenticator.CreateChallengeHandler(w, r)
	if err != nil {
		s.logger.Printf("CreateChallengeHandler error generating challenge err: %s", err)
		s.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
}

// LoginWithChallengeHandler is an example on how to handle the call to login withChallenge
// path. Notice that we fist do the authentication checks, then we create the session
// and we finalize with setting a cookie (which in this implementaiton) is used to track
// user sessions.
func (s *RuntimeState) LoginWithChallengeHandler(w http.ResponseWriter, r *http.Request) {
	authUser, authMaxAge, userErrString, err := s.websshauthenticator.LoginWithChallenge(r)
	if err != nil {
		s.logger.Printf("error=%s", err)
		errorCode := http.StatusBadRequest
		if userErrString == "" {
			errorCode = http.StatusInternalServerError
		}
		http.Error(w, userErrString, errorCode)
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
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	_, err = s.withCookieSetNewAuthCookie(w, cookieVal, maxAge)
	if err != nil {
		s.logger.Printf("error=%s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	//send OK
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")

	s.logger.Printf("Success auth %s", authUser)
}
