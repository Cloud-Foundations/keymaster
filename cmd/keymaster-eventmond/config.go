package main

import (
	"io/ioutil"
	"text/template"

	"github.com/Cloud-Foundations/keymaster/lib/constants"
	"gopkg.in/yaml.v2"
)

func loadConfig(filename string) (*configurationType, error) {
	rawConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	config := &configurationType{
		KeymasterServerPortNum: constants.DefaultKeymasterAdminPortNumber,
	}
	if err := yaml.Unmarshal(rawConfig, config); err != nil {
		return nil, err
	}
	if err := parseCommand(&config.SshCertParametersCommand); err != nil {
		return nil, err
	}
	if err := parseCommand(&config.X509CertParametersCommand); err != nil {
		return nil, err
	}
	return config, nil
}

func parseCommand(command *certCommand) error {
	for _, parameter := range command.Parameters {
		templ := template.New("")
		templ, err := templ.Parse(parameter)
		if err != nil {
			return err
		}
		command.templates = append(command.templates, templ)
	}
	return nil
}
