package u2f

import (
	"testing"
)

func TestVerifyAppId(t *testing.T) {
	passingData := map[string][]string{
		"https://good.example.com/": {
			"good.example.com",
			"https://good.example.com/",
		},
		"https://good.example.com:443/": {
			"good.example.com",
			"https://good.example.com/",
		},
	}
	invalidAppid := map[string][]string{
		"https://good.example.com/": {
			"evil.example.com",
			"https://evil.example.com/",
		},
		"https://good.example.com:443/": {
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
