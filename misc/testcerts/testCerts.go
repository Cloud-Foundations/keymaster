package testcerts

import (
	_ "embed"
)

// Files:
// eekey.pem	localhost.csr	localhost.ext	localhost.pem	root.csr	root.pem	rootkey.pem	testCerts.go

//go:embed root.pem
var RootCertPem string

//go:embed rootkey.pem
var RootKeyPem string

//go:embed localhost.pem
var LocalHostCertPem string

//go:embed eekey.pem
var LocalHostKeyPem string
