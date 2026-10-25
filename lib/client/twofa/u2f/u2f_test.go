package u2f

import (
	"testing"
)

func TestVerifyAppId(t *testing.T) {
	passingData := map[string][]string{
		"https://good.example.com/": []string{
			"good.example.com",
			"https://good.example.com/",
		},
		"https://good.example.com:443/": []string{
			"good.example.com",
			"https://good.example.com/",
		},
	}
	invalidAppid := map[string][]string{
		"https://good.example.com/": []string{
			"evil.example.com",
			"https://evil.example.com/",
		},
		"https://good.example.com:443/": []string{
			"evil.example.com",
			"https://evil.example.com/",
		},
	}
	for baseURL, appIDList := range passingData {
		for _, appId := range appIDList {
			valid, err := verifyAppId(baseURL, appId)
			if err != nil {
				t.Fatal(err)
			}
			if !valid {
				t.Fatalf("Falied to validate valid appId for base=%s, appid=%s", baseURL, appId)
			}
		}
	}
	for baseURL, appIDList := range invalidAppid {
		for _, appId := range appIDList {
			valid, err := verifyAppId(baseURL, appId)
			if err != nil {
				t.Fatal(err)
			}
			if valid {
				t.Fatalf("Falied to Invalidate invalid appId for base=%s, appid=%s", baseURL, appId)
			}
		}
	}

}

func TestWebAuthnFacet(t *testing.T) {
	tests := []struct {
		baseURL, appId, want string
	}{
		{"https://good.example.com", "https://good.example.com", "https://good.example.com"},
		{"https://good.example.com", "", "https://good.example.com"},
		{"https://good.example.com/", "", "https://good.example.com"},
		{"https://good.example.com:33443", "", "https://good.example.com:33443"},
	}
	for _, test := range tests {
		got, err := webAuthnFacet(test.baseURL, test.appId)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("base=%s appid=%q: got %s, want %s",
				test.baseURL, test.appId, got, test.want)
		}
	}
	if _, err := webAuthnFacet("good.example.com", ""); err == nil {
		t.Fatal("expected error for base URL without scheme")
	}
}
