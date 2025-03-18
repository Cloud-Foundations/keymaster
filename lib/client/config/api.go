package config

import (
	"net/http"

	"github.com/Cloud-Foundations/golib/pkg/log"
)

type BaseConfig struct {
	AddGroups        bool   `yaml:"add_groups"`
	AgentConfirmUse  bool   `yaml:"agent_confirm_use"`
	FilePrefix       string `yaml:"file_prefix"`
	Gen_Cert_URLS    string `yaml:"gen_cert_urls"`
	PreferredKeyType string `yaml:"preferred_key_type"`
	Username         string `yaml:"username"`
	WebauthBrowser   string `yaml:"webauth_browser"`
}

// AppConfigFile represents a keymaster client configuration file
type AppConfigFile struct {
	Base BaseConfig
}

// LoadVerifyConfigFile reads, verifies, and returns the contents of
// a keymaster configuration file. LoadVerifyConfigFile returns an error if the
// configuration file is invalid.
func LoadVerifyConfigFile(configFilename string) (AppConfigFile, error) {
	return loadVerifyConfigFile(configFilename)
}

// GetConfigFromHost grabs a default config file from a given host and stores
// it in the local file system.
func GetConfigFromHost(
	configFilename string,
	hostname string,
	client *http.Client,
	logger log.Logger) error {
	return getConfigFromHost(configFilename, hostname, client, logger)
}
