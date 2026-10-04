package fido

import (
	"testing"
)

func TestGetProvider(t *testing.T) {
	provider, err := GetProvider()
	if err != nil {
		t.Fatal(err)
	}
	if provider == nil {
		t.Fatal("nil provider")
	}
}
