package vip

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"
	"time"
)

const rootCAPem = `-----BEGIN CERTIFICATE-----
MIIE1jCCAr4CAQowDQYJKoZIhvcNAQELBQAwMTELMAkGA1UEBhMCVVMxEDAOBgNV
BAoMB1Rlc3RPcmcxEDAOBgNVBAsMB1Rlc3QgQ0EwHhcNMTcwMTA1MTc0NzQ1WhcN
MzYxMjMxMTc0NzQ1WjAxMQswCQYDVQQGEwJVUzEQMA4GA1UECgwHVGVzdE9yZzEQ
MA4GA1UECwwHVGVzdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AK178Hyl2iJ8l4k/iHWgACtkLLa4n6sJo6DB8s1t98ILgU5ykT30jslWPH/QJvfL
/OAvgDcq2+ScwZThGFMxotBKnoufy88wAV/8SAwdy6rbAatW6v6K8+dgPEcka2jf
aqOby27+vrglQePQjjUMZoqr4qAizCUwCGZQUPhfSorBUcyWupKVZe8kDmD395yT
yRf3z5rJAMFzJmNOv/6ZOA2Scv14xZWTezBlr3E2zBCr0iYpYsqh5dG2ube9DYyX
0fXfrfaa8jstlu9jrYltxRmlCBAdoFB1N7eN6V/CsKc9nKc4dFkNDJng1Z4dpPYW
v+HzYI4UBsnkYFtpt5VV3M+Ys/FE1ARE4ah4R69FK+eBKCkpRUszbm/fjnt/QvDX
pCBcpa8vddgAgFKz9kvpO3lfA+jBb2euzX1lOL3ETooE0sEtFPK81P2M62BxsoIa
ztAWOQlLQotDtY156YaUoREXCjLkpiitEhpn9+nlMAPlA9X2iVQWIgpkAepbu+rU
ouODruaOoxc67GyTXUT7NIj3IE3PxPn5LBta+SOJ1DsUcC7aBG/x10/ifYLq/H4J
JxnHhac+S5aKxeCBTzT84JKltbYiqhhoGVaXYp6AwbOkqUMYyhEKelcvtdKc7fKF
+0DRAymVdGzV+nhwxGqwgarlXzZwsWkSj/A0+J7l2Ty9AgMBAAEwDQYJKoZIhvcN
AQELBQADggIBAKsYxpXFY4dyarnvMjAmX6EXcwqDfOJXgQdnX7QMzYlygMb+m2h1
Nuk4HTMlmQtkLba6JQd5NQw42RBYl1ef0PwwJoVlznht7Hec9wEopa5pyzyerSPT
nblh1TRKVffLQ1SyTO6yPgdn8rct5n2M0tW+nW7SZuWkzsc6swVEfJyTykXbMYHg
aSap7oMUr0MaffQjihzwk585fY8GvPeqdrer/k7d6MD05NWkqeXaMitI4hNWTyTu
7yjppKcGRVaNHmhk4867Jz6RZzxWbZBQe7tqaqmdqKLvz8/7j/VFjBTO2NebE0FV
LxKcpv6QklH0UWqzWBn8LDZRYz6D1PglGjgh8ERHOTKJW0BRdIlzljZwND2f5lSx
0HBSJYqTU38iBCHkxf8hYdiPI8Jw2CCt4l+hCwQhtIWgCrENSIa1sT9j3TPy+zwq
2GHf9xTpjV1pVEyuFPf1bllPUeOFXprJiq2J4rnE/fqyabO0uSX35ucdG+YGVyMa
BkwaEPvqvwremmh+xLYye6scQ+A/Wn9fN/8VN0W22t37O2VQNgsTANyIZwKZlxJc
fSkkhF5M7t/rWTtO0MXnCuIDJu3QJneRvOSBlvIabkVGEt9tZQCzK9wiJqsBkLSy
FCdYqoFk7gKsLkv51iMd+oItlEBuSEJSs1N+F5knShYfJdpHYDY+84ul
-----END CERTIFICATE-----`

const localhostCertPem = `-----BEGIN CERTIFICATE-----
MIIDvTCCAaUCBQLd4CbMMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAlVTMRAw
DgYDVQQKDAdUZXN0T3JnMRAwDgYDVQQLDAdUZXN0IENBMB4XDTE3MDEwNTE3NTQw
NVoXDTM2MTIzMTE3NTQwNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3w9PziLdiuYkq4sxVEQkq0HIq6Ad/51o
k98AG87DqbG4hcPcbP/ItEHv4NdYZOtagY5twzb+sjcDC4plubQ9ewMKsGeBlDG4
xxkaMYJeqx8usmiT+fisiI6B+tM38ahxtYqcyCp3ou+WrSEuRb+70UXnztR8RT4R
ISkpq0wuj1Qcmxp9GkyA6aH4gwlj7EocqhIUCF2LxS8U0u2xvbCxHVSQFf4VxrrW
ZwoHaI8GWAZb/IAe9gxoau5rtJ90gpesO5AVx1VPX+WhpSCmVGPnJdknMXC6mjDJ
rMUW0KX8/dX7OdXAtSdDLzm6Yd4cI2DTnGVfckGIzsIYlGhBwxIUGwIDAQABMA0G
CSqGSIb3DQEBCwUAA4ICAQAlendYr/Xrh2h9tWRNB7kCS8OSaJqsaLP7nDWlwbj/
93QRB51qg2BHUy+tCzXAChq9HnaVcOLrDa0V3Amx5J6LauIBTnRBlHQGaw9Tu4Bo
UqMusHKM9/brNTDRUq8eafJhdfsXWs+cwKj9+Zh1UX0gc8yzgJSLCfkJgeuf62vP
tLAiJAxanxwT2hqtHnuVLu/UUmfx4n0IOALE8tARcLwZkKfmbsXiIY0ZIb/kwCuF
APYy4bmjRXfA9CKnHcfwOxYNqsAPad/MLme9bSBtOuY75VY3UDeno6Uz5PZL4163
8q+MedT6yinEtGaEllnpWMHa4NC0w+Klpk28fONEIxfqjCvlugRkIlCS3T9qfS9R
vhqwn1V+13JRYxLwMtVpXPdfQbBy7PG9VaQAyRsMrIGsG8esHx+OUMKP3hvh07gs
Lhmjn8SWaFpazldaNRcbOKazxHcwY+yL21VEL5CdA8GcjXEls3YaCuw54QBPJaoB
Yg4ybiaio7h8od1Nydf3mbQ9gmMruLpGHw7RKAGxBD6Ukt0uPAMKOgaL9H2YOSzB
SsYyE/ONrTbxpHZPQG1SszKuKUzGsPEwlMTwt8NHVTixKy/ttMA7NhN8KAYJrJQw
Z65R0mZFpYSL31jrfV4Q4mhFj6/Cr8rgmH++82FWfg88gf4lPk6/iDZtHvMMBUXy
Pg==
-----END CERTIFICATE-----`

const localhostKeyPem = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDfD0/OIt2K5iSr
izFURCSrQciroB3/nWiT3wAbzsOpsbiFw9xs/8i0Qe/g11hk61qBjm3DNv6yNwML
imW5tD17AwqwZ4GUMbjHGRoxgl6rHy6yaJP5+KyIjoH60zfxqHG1ipzIKnei75at
IS5Fv7vRRefO1HxFPhEhKSmrTC6PVBybGn0aTIDpofiDCWPsShyqEhQIXYvFLxTS
7bG9sLEdVJAV/hXGutZnCgdojwZYBlv8gB72DGhq7mu0n3SCl6w7kBXHVU9f5aGl
IKZUY+cl2ScxcLqaMMmsxRbQpfz91fs51cC1J0MvObph3hwjYNOcZV9yQYjOwhiU
aEHDEhQbAgMBAAECggEBALK97lFclvLK4O+lpm3D/S5OlKMSt3cxh6+WrtuZoCjH
BPoLrQKbJRVtEO+3IFoeTnQq0cHwu7/LXWFOEZ3x1KJSGaqqBqfeABdrAhZSRdIS
NrU4H/vbTUZQC9AWmWnIdPXokSHFBgFGxBMP16iEr9hOkCapFrvVtJxCA+YEMfsf
CKK9azdS/6aA4LxFKFuf7EwZz3uD5BqQXM/1vrAjmmATzE5yoJUsUPwJNwTlwTLs
53tOoZAIhYiWMXL1USXcKm3z8IJq8SgfgOUsK9X6IEEIga/IMwimPl966RlJyIsR
U4RzqG+cP5D2bC9n1M3aBUmUGcvWV7E3nVg+bbuNYIECgYEA76lfyMCbnnBzqagx
UpNR6PXn53RQicQktt+wFFexknf01ZmX+Tn3slSVtsms2xJRtUeNmljPKa7CIMWi
CaBLA2fsUjkPB0EQk6v8MzJeEJOpfFPWC+miKZhnV17rNkuuCwUdPFIz7g66/HU5
/W4gzrUkttw597cpOkOoiUrd16sCgYEA7kQzBa0ille35TlicqSQqeLQrTSga7b2
U0NjSwu0szCGw2LNV87H6Fhxw+MqIQM5VDTPb3bp9T0Uv2n0moENbGO5dD4ZGuNC
mA+AmKNeUBx81Jx4DumGxaU3eATkg6KlNKNccHtXF64k8blM9Y6q6ncCtr4UVz3H
ekSGNXx/hVECgYBf+o7XkPtBmntXqHoIPeOBzmlPMi/G3HxvmGml2/DLXar5mAda
0jI2gtVqXJ4TJeT/GmbFN2fPo6MvCLb57+3asVXdH+i62P3QhgH8ZuFw9hHcLp78
Kla9HcHVJbhBCFHtK+EndSxC3DdaP4A31FDjN3w6lzvHztx97vah9Q+e/QKBgQCk
8Y+EuXO9MmJ7DDvL84K2KO+fSFRZ3SIvR/JgDG1+svRIJIjU5bBcd4XiPst2aR3x
3lFP77lM7YkEbdxIbViWlX7YKvkENRlv3SOAB3CN8vqz0NIIOL/06Ug6DOEJA7ps
cz7WG3ySRxsKP+Y4BBjsEZFOYs4ACyOhz/g85L/+0QKBgQCjjTLjcSNg+fBZRXHC
YwzyBA/WXBPve5qo17Bt91knZ4m+xOVmRcswNG2U0eFrm+nNlk84Kj3TMRAv8Stx
GuCdIOQpn0IWClccTMjwc0AhJStSckNdSUQcsRl6LRnRHa3oCIs3hxnkiEHYch6e
dcxWzhBDbzeIV9SvcTwLx/ghQg==
-----END PRIVATE KEY-----`

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
