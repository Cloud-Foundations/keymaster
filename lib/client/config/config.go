package config

import (
	"errors"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/Cloud-Foundations/Dominator/lib/log"
	"gopkg.in/yaml.v2"
)

func loadVerifyConfigFile(configFilename string) (AppConfigFile, error) {
	var config AppConfigFile
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("No config file: please re-run with -configHost")
		return config, err
	}
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		err = errors.New("cannot read config file")
		return config, err
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		err = errors.New("Cannot parse config file")
		return config, err
	}

	if len(config.Base.Gen_Cert_URLS) < 1 {
		err = errors.New("Invalid Config file... no place get the certs")
		return config, err
	}
	// TODO: ensure all enpoints are https urls

	return config, nil
}

const hostConfigPath = "/public/clientConfig"

func getConfigFromHost(
	configFilename string,
	hostname string,
	client *http.Client,
	logger log.Logger) error {
	configUrl := "https://" + hostname + hostConfigPath
	resp, err := client.Get(configUrl)
	if err != nil {
		logger.Printf("got error from req")
		logger.Println(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logger.Printf("got error from getconfig call %s", resp)
		return err
	}
	configData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configFilename, configData, 0644)
}
