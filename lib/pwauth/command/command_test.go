package command

import (
	"testing"

	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
)

func TestTrueCommand(t *testing.T) {
	pa, err := New("true", nil, testlogger.New(t))
	if err != nil {
		t.Fatalf("unable to create PasswordAuthenticator")
	}
	if ok, err := pa.PasswordAuthenticate("u", []byte("p")); !ok {
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		} else {
			t.Fatalf("true did not return 0")
		}
	}
}

func TestFalseCommand(t *testing.T) {
	pa, err := New("false", nil, testlogger.New(t))
	if err != nil {
		t.Fatalf("unable to create PasswordAuthenticator")
	}
	if ok, err := pa.PasswordAuthenticate("u", []byte("p")); !ok {
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	} else {
		t.Fatalf("false did not return 1")
	}
}

func TestMissingCommand(t *testing.T) {
	_, err := New("/should-not-exist/test.foo-bar_baz", nil, testlogger.New(t))
	if err == nil {
		t.Fatalf("missing command did not generate error")
	}
}

func TestBrokenCommand(t *testing.T) {
	pa, err := New("true", nil, testlogger.New(t))
	if err != nil {
		t.Fatalf("unable to create PasswordAuthenticator")
	}
	pa.command = "/should-not-exist/test.foo-bar_baz"
	if _, err := pa.PasswordAuthenticate("u", []byte("p")); err == nil {
		t.Fatalf("missing command did not generate error")
	}
}
