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
				t.Fatalf("Falied to INvalidate valid appId for base=%s, appid=%s", baseURL, appId)
			}
		}
	}

}
