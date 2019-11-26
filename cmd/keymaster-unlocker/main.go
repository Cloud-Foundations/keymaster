package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/Cloud-Foundations/Dominator/lib/log/cmdlogger"
	"github.com/howeyc/gopass"
)

var (
	Version    = "No version provided"
	certFile   = flag.String("cert", "client.pem", "A PEM eoncoded certificate file.")
	keyFile    = flag.String("key", "key.pem", "A PEM encoded private key file.")
	targetHost = flag.String("keymasterHostname", "", "The hostname/port for keymaster")
	targetPort = flag.Int("keymasterPort", 6920, "The port for keymaster control port")
)

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	logger := cmdlogger.New()

	if len(*targetHost) < 1 {
		logger.Fatal("keymasterHostname paramteter  is required")
	}

	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		logger.Fatal(err)
	}

	fmt.Printf("Password for unlocking %s: ", *targetHost)
	password, err := gopass.GetPasswd()
	if err != nil {
		logger.Fatal(err)
		// Handle gopass.ErrInterrupted or getch() read error
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Do GET something
	resp, err := client.PostForm("https://"+*targetHost+":"+strconv.Itoa(*targetPort)+"/admin/inject",
		url.Values{"ssh_ca_password": {string(password[:])}})
	//resp, err := client.Get("https://goldportugal.local:8443")
	if err != nil {
		logger.Fatal(err)
	}
	defer resp.Body.Close()

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Println(string(data))
}
