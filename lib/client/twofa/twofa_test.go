package twofa

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
	"github.com/Cloud-Foundations/keymaster/lib/client/util"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

const testUserPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI09fpMWTeYw7/EO/+FywS/sghNXdTeTWxX7K2N17owsQJX8s76LGVIdVeYrWg4QSmYlpf6EVSCpx/fbCazrsG7FJVTRhExzFbRT9asmvzS+viXSbSvnavhOz/paihyaMsVPKVv24vF6MOs8DgfwehcKCPjKoIPnlYXZaZcy05KOcZmsvYu2kNOP6sSjDFF+ru+T+DLp3DUGw+MPr45IuR7iDnhXhklqyUn0d7ou0rOHXz9GdHIzpr+DAoQGmTDkpbQEo067Rjfu406gYL8pVFD1F7asCjU39llQCcU/HGyPym5fa29Nubw0dzZZXGZUVFalxo02YMM7P9I6ZjeCsv cviecco@example.com`

func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(localhostCertPem), []byte(localhostKeyPem))
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS11,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
	}, nil
}

const localHttpsTarget = "https://localhost:22443/"

var testAllowedCertBackends = []string{proto.AuthTypePassword, proto.AuthTypeU2F}

func handler(w http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{Name: "somename", Value: "somevalue"}
	http.SetCookie(w, &authCookie)
	switch r.URL.Path {
	case proto.LoginPath:
		loginResponse := proto.LoginResponse{Message: "success",
			CertAuthBackend: testAllowedCertBackends}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)

	default:
		fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	}
}

func init() {
	tlsConfig, _ := getTLSconfig()
	//_, _ = tls.Listen("tcp", ":11443", config)
	srv := &http.Server{
		Addr:      "127.0.0.1:22443",
		TLSConfig: tlsConfig,
	}
	http.HandleFunc("/", handler)
	go srv.ListenAndServeTLS("", "")
	//http.Serve(ln, nil)
}

func TestGetCertFromTargetUrlsSuccessOneURL(t *testing.T) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	tlsConfig := &tls.Config{RootCAs: certPool, MinVersion: tls.VersionTLS12}
	client, err := util.GetHttpClient(tlsConfig, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := util.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	skipu2f := true
	_, _, _, err = GetCertFromTargetUrls(
		privateKey,
		"username",
		[]byte("password"),
		[]string{localHttpsTarget},
		skipu2f,
		false,
		client,
		"someUserAgent",
		testlogger.New(t)) //(cert []byte, err error)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetCertFromTargetUrlsFailUntrustedCA(t *testing.T) {
	privateKey, err := util.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	client, err := util.GetHttpClient(tlsConfig, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	skipu2f := true
	_, _, _, err = GetCertFromTargetUrls(
		privateKey,
		"username",
		[]byte("password"),
		[]string{localHttpsTarget},
		skipu2f,
		false,
		client,
		"someUserAgent",
		testlogger.New(t))
	if err == nil {
		t.Fatal("Should have failed to connect untrusted CA")
	}
}
