package twofa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
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
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
	}, nil
}

const localHttpsTarget = "https://localhost:22443/"

var defaultTestAllowedCertBackends = []string{proto.AuthTypePassword, proto.AuthTypeU2F}
var testAllowedCertBackends = defaultTestAllowedCertBackends
var testAuthCookieName = "testAuthCookie"

func handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case proto.LoginPath:
		authCookie := http.Cookie{Name: testAuthCookieName, Value: "somevalue", Path: "/"}
		http.SetCookie(w, &authCookie)
		loginResponse := proto.LoginResponse{Message: "success",
			CertAuthBackend: testAllowedCertBackends}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)
	case "/certgen/username":
		//check if there is a cookie
		cookies := r.Cookies()
		fmt.Printf("on test here is the request cookies %+v", cookies)
		if len(cookies) < 1 {
			w.WriteHeader(401)
			return
		}
		fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	case "/api/v0/TOTPAuth":
		cookies := r.Cookies()
		fmt.Printf("on test here is the request cookies %+v", cookies)
		if len(cookies) < 1 {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
		loginResponse := proto.LoginResponse{Message: "success",
			CertAuthBackend: testAllowedCertBackends}
		json.NewEncoder(w).Encode(loginResponse)
	default:
		w.WriteHeader(400)
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

func TestAAuthenticateToTargetUrlsFailUntrustedCA(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	client, err := util.GetHttpClient(tlsConfig, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	skipu2f := true
	_, err = AuthenticateToTargetUrls(
		"username",
		[]byte("password"),
		[]string{localHttpsTarget},
		skipu2f,
		client,
		"someUserAgent",
		testlogger.New(t))
	if err == nil {
		t.Fatal("Should have failed to connect untrusted CA")
	}
}

func pipeToStdin(s string) (int, error) {
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		fmt.Println("Error getting os pipes:", err)
		os.Exit(1)
	}
	os.Stdin = pipeReader
	w, err := pipeWriter.WriteString(s)
	pipeWriter.Close()
	return w, err
}

func TestAuthenticateToTargetUrlsSuccessOneURL(t *testing.T) {
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
	_, err = AuthenticateToTargetUrls(
		"username",
		[]byte("password"),
		[]string{localHttpsTarget},
		false,
		client,
		"someUserAgent",
		testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	//Now Totp?
	testAllowedCertBackends = []string{proto.AuthTypeTOTP}
	defer func() {
		testAllowedCertBackends = defaultTestAllowedCertBackends
	}()
	_, err = pipeToStdin("123456\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = AuthenticateToTargetUrls(
		"username",
		[]byte("password"),
		[]string{localHttpsTarget},
		false,
		client,
		"someUserAgent",
		testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
}

func TestDoCertRequestSuccess(t *testing.T) {
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
	// 1024 because we are not actually checking for security in this test
	signer, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	// set cookie in jar
	// "net/http/cookiejar
	// func (j *Jar) SetCookies(u *url.URL, cookies []*http.Cookie)
	authCookie := http.Cookie{Name: testAuthCookieName, Value: "somevalue", Path: "/"}
	parsedURL, err := url.Parse(localHttpsTarget)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar.SetCookies(parsedURL, []*http.Cookie{&authCookie})
	_, err = DoCertRequest(signer, client, "username", localHttpsTarget, "x509",
		false, "someUserAgent", testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DoCertRequest(signer, client, "username", localHttpsTarget, "x509-kubernetes",
		false, "someUserAgent", testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DoCertRequest(signer, client, "username", localHttpsTarget, "ssh",
		false, "someUserAgent", testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DoCertRequest(signer, client, "username", localHttpsTarget, "invalidtype",
		false, "someUserAgent", testlogger.New(t))
	if err == nil {
		t.Fatalf("Should have failed for invalid cert type")
	}
}
