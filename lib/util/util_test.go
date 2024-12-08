package util

import (
	"net/http"
	"testing"
)

func TestGetRequestRealIp(t *testing.T) {
	// Simple match
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "10.0.0.1:12345"

	remoteIP := GetRequestRealIp(req)
	if remoteIP != "10.0.0.1" {
		t.Fatal("simple match failed")
	}

	// With X-Forwarded-For (success path)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	remoteIP = GetRequestRealIp(req)
	if remoteIP != "203.0.113.195" {
		t.Fatalf("simple match failed got %s", remoteIP)
	}
	// now ipv6
	ipv6addr := "2001:db8:85a3:8d3:1319:8a2e:370:7348"
	req.RemoteAddr = ipv6addr
	req.Header.Set("X-Forwarded-For", ipv6addr)
	remoteIP = GetRequestRealIp(req)
	if remoteIP != ipv6addr {
		t.Fatalf("simple match failed got %s", remoteIP)
	}
	// todo... with chain
	// 203.0.113.195,2001:db8:85a3:8d3:1319:8a2e:370:7348,198.51.100.178
}

func TestCreateSimpleDataBodyRequestSuccess(t *testing.T) {
	req, err := CreateSimpleDataBodyRequest("GET", "/", []byte("some-content"), "mimte-content-type")
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("req must NOT be null")
	}
}

func TestCreateFormDataBodyRequestSimple(t *testing.T) {
	req, err := CreateFormDataBodyRequest("GET", "/", "filedata", "file-field-name", "filename")
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("req must NOT be null")
	}
}
