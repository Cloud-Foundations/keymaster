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
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/log/cmdlogger"
	"github.com/Cloud-Foundations/golib/pkg/log"
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
	retryInterval = flag.Duration("retryInterval", 0, "If > 0: retry")
)

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func getPassword(password string) (string, error) {
	if password == "" {
		fmt.Printf("Password for unlocking %s: ", *keymasterHostname)
		passwd, err := gopass.GetPasswd()
		if err != nil {
			return "", err
			// Handle gopass.ErrInterrupted or getch() read error
		}
		password = string(passwd)
	}
	return password, nil
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
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert},
		MinVersion: tls.VersionTLS12}
	tlsConfig.BuildNameToCertificate()
	clients := makeClients(addrs, tlsConfig)
	var password string
	if *retryInterval > 0 {
		if password, err = getPassword(password); err != nil {
			logger.Fatal(err)
		}
		if *retryInterval < time.Second {
			*retryInterval = time.Second
		}
		for {
			unseal(addrs, clients, password, logger)
			time.Sleep(*retryInterval)
		}
	} else {
		unseal(addrs, clients, password, logger)
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

func testReady(client *http.Client) (bool, error) {
	resp, err := client.Get("https://" + *keymasterHostname + ":" +
		strconv.Itoa(*keymasterPort) + "/readyz")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	// Older keymasters are assumed to not be ready.
	return resp.StatusCode == 200, nil
}

func unseal(addrs []string, clients []*http.Client, password string,
	logger log.Logger) {
	for index, client := range clients {
		ready, err := testReady(client)
		if err != nil {
			logger.Printf("%s: %s\n", addrs[index], err)
			continue
		}
		if ready {
			logger.Printf("%s: already unsealed\n", addrs[index])
			continue
		}
		password, err = getPassword(password)
		if err != nil {
			logger.Fatal(err)
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
