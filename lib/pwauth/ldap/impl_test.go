package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	//	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/simplestorage/memstore"

	"github.com/vjeantet/ldapserver"
)

type ServerConfig struct {
	Delay     time.Duration
	ValidUser string
}

var (
	serverMmutex = &sync.Mutex{}
	serverConfig = ServerConfig{ValidUser: "username",
		Delay: 0 * time.Millisecond}
)

// getTLSconfig returns a tls configuration used
// to build a TLSlistener for TLS or StartTLS
func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(localhostCertPem), []byte(localhostKeyPem))
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionSSL30,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
	}, nil
}

// handleBind return Success if login == username
func handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetBindRequest()
	res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)

	serverMmutex.Lock()
	config := serverConfig
	serverMmutex.Unlock()

	time.Sleep(config.Delay)

	if string(r.Name()) == config.ValidUser {
		w.Write(res)
		return
	}

	log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
	res.SetResultCode(ldapserver.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}

func init() {
	//Create a new LDAP Server
	server := ldapserver.NewServer()

	//Set routes, here, we only serve bindRequest
	routes := ldapserver.NewRouteMux()
	routes.Bind(handleBind)
	server.Handle(routes)

	//SSL
	secureConn := func(s *ldapserver.Server) {
		config, _ := getTLSconfig()
		s.Listener = tls.NewListener(s.Listener, config)
	}
	go server.ListenAndServe("127.0.0.1:10640", secureConn)

	//we also make a simple tls listener
	//
	config, _ := getTLSconfig()
	ln, _ := tls.Listen("tcp", "127.0.0.1:10639", config)
	go func(ln net.Listener) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			//log.Printf("Got connection!!!!")
			conn.Write([]byte("hello\n"))
			conn.Close()
		}
	}(ln)
	// On single core systems we needed to ensure that the server is started before
	// we create other testing goroutines. By sleeping we yield the cpu and allow
	// ListenAndServe to progress
	time.Sleep(20 * time.Millisecond)
}

const localLDAPSURL = "ldaps://localhost:10640"

func TestPasswordAuthetnicateSimple(t *testing.T) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	authn, err := newAuthenticator([]string{localLDAPSURL}, []string{"%s"}, 0, certPool, nil, nil)
	//ok, err := CheckHtpasswdUserPassword("username", "password", []byte(userdbContent))
	if err != nil {
		t.Fatal(err)
	}

	serverMmutex.Lock()
	serverConfig.ValidUser = "username"
	serverConfig.Delay = 0 * time.Millisecond
	serverMmutex.Unlock()

	ok, err = authn.passwordAuthenticate("username", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if ok != true {
		t.Fatal("User considerd false")
	}

	ok, err = authn.passwordAuthenticate("invalidUser", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if ok != false {
		t.Fatal("User considerd true")
	}

}

func TestPasswordAuthetnicateCache(t *testing.T) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	cache := memstore.New()
	authn, err := newAuthenticator([]string{localLDAPSURL}, []string{"%s"}, 1, certPool, cache, nil)
	//ok, err := CheckHtpasswdUserPassword("username", "password", []byte(userdbContent))
	if err != nil {
		t.Fatal(err)
	}
	ok, err = authn.passwordAuthenticate("username", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if ok != true {
		t.Fatal("User considerd false")
	}
	start := time.Now()
	serverMmutex.Lock()
	serverConfig.ValidUser = "username"
	serverConfig.Delay = 5000 * time.Millisecond
	serverMmutex.Unlock()
	ok, err = authn.passwordAuthenticate("username", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if ok != true {
		t.Fatal("User considerd false")
	}
	end := time.Now()
	if end.Sub(start) > 2000*time.Millisecond {
		t.Fatal("timeout did not work as expected")
	}

	//lets make it an indalid user
	serverMmutex.Lock()
	serverConfig.ValidUser = "otheruser"
	serverConfig.Delay = 0 * time.Millisecond
	serverMmutex.Unlock()

	ok, err = authn.passwordAuthenticate("username", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if ok != false {
		t.Fatal("User considerd true")
	}
	//and ass timeout and the auth should fail as the cache should have been cleared
	serverMmutex.Lock()
	serverConfig.ValidUser = "username"
	serverConfig.Delay = 5000 * time.Millisecond
	serverMmutex.Unlock()

	ok, err = authn.passwordAuthenticate("username", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if ok != false {
		t.Fatal("User considerd true")
	}

	// now lets set the expiration to 1ms and ensure that the cache is filled up
	serverMmutex.Lock()
	serverConfig.ValidUser = "username"
	serverConfig.Delay = 0 * time.Millisecond
	serverMmutex.Unlock()
	authn.expirationDuration = 0 * time.Millisecond
	ok, err = authn.passwordAuthenticate("username", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if ok != true {
		t.Fatal("User considerd false")
	}
	/// and now add the timeout... since it is expired it should return false
	serverMmutex.Lock()
	serverConfig.ValidUser = "username"
	serverConfig.Delay = 5000 * time.Millisecond
	serverMmutex.Unlock()

	ok, err = authn.passwordAuthenticate("username", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if ok != false {
		t.Fatal("User considerd true")
	}

}
