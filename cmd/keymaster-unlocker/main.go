package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Cloud-Foundations/Dominator/lib/log/cmdlogger"
	"github.com/howeyc/gopass"
)

var (
	Version  = "No version provided"
	certFile = flag.String("cert", "client.pem",
		"A PEM encoded certificate file.")
	keyFile = flag.String("key", "key.pem",
		"A PEM encoded private key file.")
	keymasterHostname = flag.String("keymasterHostname", "",
		"The hostname for keymaster")
	keymasterPort = flag.Int("keymasterPort", 6920,
		"The keymaster control port")
)

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	logger := cmdlogger.New()
	if len(*keymasterHostname) < 1 {
		logger.Fatal("keymasterHostname paramteter  is required")
	}
	addrs, err := net.LookupHost(*keymasterHostname)
	if err != nil {
		logger.Fatal(err)
	}
	if len(addrs) < 1 {
		logger.Fatalf("no addresses for: %s\n", *keymasterHostname)
	}
	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		logger.Fatal(err)
	}
	// Setup HTTPS clients.
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.BuildNameToCertificate()
	clients := makeClients(addrs, tlsConfig)
	var password string
	for index, client := range clients {
		unsealed, err := testUnsealed(client)
		if err != nil {
			logger.Printf("%s: %s\n", addrs[index], err)
			continue
		}
		if unsealed {
			logger.Printf("%s: already unsealed\n", addrs[index])
			continue
		}
		if password == "" {
			fmt.Printf("Password for unlocking %s: ", *keymasterHostname)
			passwd, err := gopass.GetPasswd()
			if err != nil {
				logger.Fatal(err)
				// Handle gopass.ErrInterrupted or getch() read error
			}
			password = string(passwd)
		}
		resp, err := client.PostForm("https://"+*keymasterHostname+":"+
			strconv.Itoa(*keymasterPort)+"/admin/inject",
			url.Values{"ssh_ca_password": {password}})
		if err != nil {
			logger.Printf("%s: %s\n", addrs[index], err)
			continue
		}
		defer resp.Body.Close()
		// Show response.
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Printf("%s: %s\n", addrs[index], err)
			continue
		}
		logger.Printf("%s: %s\n", addrs[index], strings.TrimSpace(string(data)))
	}
}

func makeClients(addrs []string, tlsConfig *tls.Config) []*http.Client {
	clients := make([]*http.Client, 0, len(addrs))
	dialer := &net.Dialer{}
	for _, addr := range addrs {
		addr := addr // Make a unique copy for the closure.
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext: func(ctx context.Context, network, hAddr string) (
				net.Conn, error) {
				_, port, err := net.SplitHostPort(hAddr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, addr+":"+port)
			},
		}
		clients = append(clients, &http.Client{Transport: transport})
	}
	return clients
}

func testUnsealed(client *http.Client) (bool, error) {
	resp, err := client.Get("https://" + *keymasterHostname + ":" +
		strconv.Itoa(*keymasterPort) + "/admin/checkSealed")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(string(data)) == "UNSEALED" {
		return true, nil
	}
	return false, nil // Older keymasters are assumed to be sealed.
}
