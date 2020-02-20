package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"testing"
)

// symmtrically gpg encrypted with password "password"
const encryptedTestSignerPrivateKey = `-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.0.22 (GNU/Linux)

jA0EAwMCcbfT9PQ87i/ZyeqXE353E4hV/gIydHlfgw7G7ybSniVuLGR8C9WpBx0o
znCGTj4qL2HKgw3wHsahK3LtMioiVmRwnzcfOW+RJxpPZL04NIb+dlkIOodZ5ci2
vqkhe23TdTHTz4XhScWe+0K+LxXeNWn5FjuApMxGnQpCbHtxnd5hTiMTTRKualZG
CPDnqy6ngXkFe5bu5nP6jsqTiWe/qZceng6MYKGHwZRZrBT1oZoL0JYXiBFVz/31
QiZA+24eTRiWcru/1d3HTc34NnHm9MTCH855Y9WtSsQq7y9Lu34NLqEuxdvhYtN9
a6jn4WASuXQgiA7kiOfH3F/9wVlnmXCgi9pvrSsiIhe3ve7NwhRva5fwj4c9BbiD
ZhwyvUC9743owKG6djk06k9cCVooIJnRwmtILKmizRqoJifepkyoJyNtKbJO3MMA
UV2D6MTqH6p29Jdud6VzmVvC6ka3GbHmrsV/I7axqwRV9cA8HwOl+i/7ZqX+ehKG
3DAySJwE3v5NrV2XRk5DUhFrfgHIziFJaa6JOO2M4wBVn9n+hhX0a3czGdM1dnA/
5ncVjJ4M+n4KmEkHAxGrIfM3+egv4arClBo5Y91ltwZLdmh5iKPOUN4x9hpA/ICy
2qSW80qVR5KNgW8vn4CW8MSjTHPMa6Upds42lKUJDYeXkEqGCpvt9izdEjTnnCrq
mRJoGO1N9Oz4ih8JRXaAVCbNbUteZmYREfGfbd8L01Zj6JQCm40G2i/5b0C79yXA
F1RtTaLSHg1guL243SMfTc+83FQ3epAJnJNaYLVKzCrIfd1Ez+bX9N99Zcik64Rx
kIGLOm1ys/bYerONpMSvRDQYYp6uHKUL7Fp1WajCVGR5L0GyHvirvA73R5mMdS/Q
8tWelKu2V6bAhSKElSHHnmToWTiJS98V/hW8RIT9kkqSdecX87UisH7WOZR/JIql
uo1ezuSO0L6gKLKUCzIqK49ppbVXGHkLYP5/a4qBwGU8v89SihLoA4obQuN/eV0n
VaPC3FXN2P1OM4q981tDxDcrDtZ31Z3uz+N8CZPaalQJLzCY2OKUsvembQuFD2l6
S9f6IWGZXhYq8BRw0+VEcnAf8oG0AWlAycAAkAaLxOj53dJLP8sK9q0M+M+yimCB
72hZg4HFgVzXsDcmYtkjlvOiOrXBUDXwzLbEDZuzCYposdWnnam2TMzj6d+psOvJ
WYyl70ZLZUs4RHIq4MB9fZyd1Oo3S/IvVbbfyaFVmvGIaGdZJ1pYFYK2USpfhrKj
ucfnXtWr9UHnSEiof9dLAtwYo2jLvs58+142gzJH7L3DYpI9kmQtf0i+gEyZ+fgN
3CRFCAP8ancFcgFeCXiFYUlPZz0pnEK8jSP7OVhEEICWwHSlD8qauT35xPeL2zf3
HWHTf9Fm+hd9AMWz6izgUbFIw4iLVmvp4FYc0C8SWUyUBasU2DKsjJH8Q1/Vy78h
hf80/+FrB8U3ETJV/T2dGFuFwOmSeaMNGOlK2OBM+Ch4lE1xiWPcp/yXzhLU/J92
vWYfnWNomDDFGad4eR8JPAT7sHJ20t8ihGMOKkfQDHt64F4pE0a3h35Tw9xxZpL0
bNcwEKLlQzbXItC0sqiQrgDNZZI8ZDEmL9FK42IKhoH7cL2siTDKDU0KmxJcbSKJ
B6TBdSkIkx6wGwrmAgtQ7D3A1PdFVDOdgQ72qWXzcDBAa5+ev9XefLdfmcbe726o
H75JiRm3pbOn5cE5lux680VJLITirQRFwR1/8lYfTLBisX44VIdmFRcFQDXrRqBU
WUGURkRA8g==
=ym0B
-----END PGP MESSAGE-----`

func TestInjectingSecret(t *testing.T) {
	var state RuntimeState
	passwdFile, err := setupPasswdFile()
	if err != nil {
		t.Fatal(err)
	}
	state.SSHCARawFileContent = []byte(encryptedTestSignerPrivateKey)
	state.SignerIsReady = make(chan bool, 1)

	defer os.Remove(passwdFile.Name()) // clean up
	state.Config.Base.HtpasswdFilename = passwdFile.Name()

	// Make certgen Request
	//Fist we ensure OK is working
	certGenReq, err := createKeyBodyRequest("POST", "/certgen/username?type=x509", testUserPEMPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	/*
		cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeU2F)
		if err != nil {
			t.Fatal(err)
		}
	*/
	cookieVal := "1234"
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	certGenReq.AddCookie(&authCookie)

	//certGenReq, err := createBasicAuthRequstWithKeyBody("POST", "/certgen/username", "username", "password", testUserSSHPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(certGenReq, state.certGenHandler, http.StatusInternalServerError)
	if err != nil {
		t.Fatal(err)
	}

	// Now we make the inject Request
	injectSecretRequest, err := http.NewRequest("POST", "/admin/inject", nil)
	if err != nil {
		t.Fatal(err)
	}
	var connectionState tls.ConnectionState
	injectSecretRequest.TLS = &connectionState

	_, err = checkRequestHandlerCode(injectSecretRequest, state.secretInjectorHandler, http.StatusForbidden)
	if err != nil {
		t.Fatal(err)
	}

	// now lets pretend that a tls connection with valid certs exists and try again
	var subjectCert x509.Certificate
	subjectCert.Subject.CommonName = "foo"
	peerCertList := []*x509.Certificate{&subjectCert}
	connectionState.VerifiedChains = append(connectionState.VerifiedChains, peerCertList)
	injectSecretRequest.TLS = &connectionState

	q := injectSecretRequest.URL.Query()
	q.Add("ssh_ca_password", "password")
	injectSecretRequest.URL.RawQuery = q.Encode()

	_, err = checkRequestHandlerCode(injectSecretRequest, state.secretInjectorHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

	if state.Signer == nil {
		t.Errorf("The signer should now be loaded")
	}

	cookieVal, err = state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie = http.Cookie{Name: authCookieName, Value: cookieVal}
	certGenReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(certGenReq, state.certGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}
