package main

import (
	"flag"
	"log"
	"path"
	"text/template"

	"github.com/Cloud-Foundations/Dominator/lib/log/serverlogger"
	"github.com/Cloud-Foundations/keymaster/eventmon/eventrecorder"
	"github.com/Cloud-Foundations/keymaster/eventmon/httpd"
	"github.com/Cloud-Foundations/keymaster/eventmon/monitord"
	"github.com/Cloud-Foundations/keymaster/lib/constants"
	"github.com/Cloud-Foundations/keymaster/proto/eventmon"
	"github.com/Cloud-Foundations/tricorder/go/tricorder"
)

var (
	configFile = flag.String("configFile",
		constants.DefaultKeymasterEventmonConfigFile, "Configuration file")
	portNum = flag.Uint("portNum", constants.DefaultEventmonPortNumber,
		"Port number to allocate and listed on for HTTP/RPC")
	stateDir = flag.String("stateDir",
		constants.DefaultKeymasterEventmonStateDir, "Saved state directory")
)

type configurationType struct {
	KeymasterServerHostname   string      `yaml:"keymaster_server_hostname"`
	KeymasterServerPortNum    uint        `yaml:"keymaster_server_port_num"`
	SshCertParametersCommand  certCommand `yaml:"ssh_cert_parameters_command"`
	SshCertRawCommand         string      `yaml:"ssh_cert_raw_command"`
	X509CertParametersCommand certCommand `yaml:"x509_cert_parameters_command"`
	X509CertRawCommand        string      `yaml:"x509_cert_raw_command"`
}

type certCommand struct {
	Command    string   `yaml:"command"`
	Parameters []string `yaml:"parameters"`
	templates  []*template.Template
}

func main() {
	flag.Parse()
	tricorder.RegisterFlags()
	logger := serverlogger.NewWithFlags("", log.LstdFlags|log.Lmicroseconds)
	configuration, err := loadConfig(*configFile)
	if err != nil {
		logger.Fatalf("Cannot load configuration: %s\n", err)
	}
	recorder, err := eventrecorder.New(path.Join(*stateDir, "events.gob"),
		logger)
	if err != nil {
		logger.Fatalf("Cannot start event recorder: %s\n", err)
	}
	monitor, err := monitord.New(configuration.KeymasterServerHostname,
		configuration.KeymasterServerPortNum, logger)
	if err != nil {
		logger.Fatalf("Cannot start monitor: %s\n", err)
	}
	httpd.AddHtmlWriter(monitor)
	httpd.AddHtmlWriter(logger)
	if err = httpd.StartServer(*portNum, recorder, monitor, true); err != nil {
		logger.Fatalf("Unable to create http server: %s\n", err)
	}
	for {
		select {
		case auth := <-monitor.AuthChannel:
			data := &eventrecorder.AuthInfo{Username: auth.Username}
			switch auth.AuthType {
			case eventmon.AuthTypePassword:
				data.AuthType = eventrecorder.AuthTypePassword
			case eventmon.AuthTypeSymantecVIP:
				data.AuthType = eventrecorder.AuthTypeSymantecVIP
				if auth.VIPAuthType == eventmon.VIPAuthTypeOTP {
					data.VIPAuthType = eventrecorder.VIPAuthTypeOTP
				} else if auth.VIPAuthType == eventmon.VIPAuthTypePush {
					data.VIPAuthType = eventrecorder.VIPAuthTypePush
				}
			case eventmon.AuthTypeU2F:
				data.AuthType = eventrecorder.AuthTypeU2F
			default:
				continue
			}
			recorder.AuthChannel <- data
		case spLogin := <-monitor.ServiceProviderLoginChannel:
			data := &eventrecorder.SPLoginInfo{
				URL:      spLogin.URL,
				Username: spLogin.Username,
			}
			recorder.ServiceProviderLoginChannel <- data
		case cert := <-monitor.SshCertChannel:
			recorder.SshCertChannel <- cert
			configuration.SshCertParametersCommand.processSshCert(cert)
		case cert := <-monitor.SshRawCertChannel:
			processRawCert(configuration.SshCertRawCommand, cert)
		case username := <-monitor.WebLoginChannel:
			recorder.WebLoginChannel <- username
		case cert := <-monitor.X509CertChannel:
			recorder.X509CertChannel <- cert
			configuration.X509CertParametersCommand.processX509Cert(cert)
		case cert := <-monitor.X509RawCertChannel:
			processRawCert(configuration.X509CertRawCommand, cert)
		}
	}
}
