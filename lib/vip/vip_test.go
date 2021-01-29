package vip

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// These two are actual working values for the validate api
const exampleResponseValueTextFail = `<?xml version="1.0" encoding="UTF-8"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Body>
    <AuthenticateCredentialsResponse xmlns="https://schemas.symantec.com/vip/2011/04/vipuserservices">
      <requestId>1234567</requestId>
      <status>6009</status>
      <statusMessage>Authentication failed.</statusMessage>
      <detail>49B5</detail>
      <detailMessage>Failed with an invalid OTP</detailMessage>
    </AuthenticateCredentialsResponse>
  </S:Body>
</S:Envelope>`
const exampleRequestValueText = `<?xml version="1.0" encoding="UTF-8" ?> <SOAP-ENV:Envelope
        xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:ns3="http://www.w3.org/2000/09/xmldsig#"
        xmlns:ns1="http://www.verisign.com/2006/08/vipservice">
        <SOAP-ENV:Body>
                <ns1:Validate Version="2.0" Id="CDCE1500"> <ns1:TokenId>AVT333666999</ns1:TokenId> <ns1:OTP>534201</ns1:OTP>
                </ns1:Validate>
        </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`

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

const localHttpsTarget = "https://localhost:23443/"

//var testAllowedCertBackends = []string{proto.AuthTypePassword, proto.AuthTypeU2F}

func handler(w http.ResponseWriter, r *http.Request) {
	//authCookie := http.Cookie{Name: "somename", Value: "somevalue"}
	//http.SetCookie(w, &authCookie)
	switch r.URL.Path {
	case "/validate/fail":
		fmt.Printf("inside validate/fail")
		fmt.Fprintf(w, "%s", exampleResponseValueTextFail)
	default:
		fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	}
}

func init() {
	tlsConfig, _ := getTLSconfig()
	//_, _ = tls.Listen("tcp", ":11443", config)
	srv := &http.Server{
		Addr:      "127.0.0.1:23443",
		TLSConfig: tlsConfig,
	}
	http.HandleFunc("/", handler)
	go srv.ListenAndServeTLS("", "")
	time.Sleep(20 * time.Millisecond)
}

func TestVerifySingleTokenFail(t *testing.T) {
	client, err := NewClient([]byte(localhostCertPem), []byte(localhostKeyPem))
	if err != nil {
		t.Fatal(err)
	}
	client.VipUserServiceAuthenticationURL = localHttpsTarget + "validate/fail"
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	client.RootCAs = certPool

	ok, err = client.VerifySingleToken("tokenID", 123456)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Log("should have failed")
		t.Fatal(err)
	}
}
