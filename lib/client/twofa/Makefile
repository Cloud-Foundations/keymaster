#this is macos/linux makefile to build the test keys


all: testcerts_test.go cleanint

testcerts_test.go: localhost.pem root.pem eekey.pem
	echo "package twofa\n\nconst rootCAPem = \``cat root.pem`\`\n\nconst localhostCertPem = \``cat localhost.pem`\`\n\nconst localhostKeyPem = \``cat eekey.pem`\`\n\n" > testcerts_test.go

localhost.pem: localhost.csr localhost.ext root.pem
	openssl  x509 -req -sha256 -days 7300 -CAkey rootkey.pem -CA root.pem -set_serial 12312389324 -out localhost.pem -in localhost.csr  -extfile localhost.ext


localhost.csr: eekey.pem
	openssl req -new -key eekey.pem -batch -out localhost.csr -utf8 -subj '/CN=localhost'

localhost.ext:
	echo "basicConstraints = CA:FALSE\nsubjectAltName =DNS:localhost\nextendedKeyUsage =serverAuth\n" > localhost.ext

eekey.pem:
	openssl genpkey -algorithm RSA -out eekey.pem -pkeyopt rsa_keygen_bits:2048

root.pem: root.csr rootkey.pem   
	openssl x509 -req -sha256 -days 7300 -in root.csr -signkey rootkey.pem -set_serial 10  -out root.pem

root.csr: rootkey.pem
	openssl req -new -key rootkey.pem  -out root.csr -utf8 -subj '/C=US/O=TestOrg/OU=Test CA'

root.ext:
	echo "basicConstraints = CA:TRUE\n" > root.ext

rootkey.pem:
	openssl genpkey -algorithm RSA -out rootkey.pem -pkeyopt rsa_keygen_bits:4096

clean: cleanint
	rm -f testcerts_test.go

cleanint:
	rm -f root.csr
	rm -f rootkey.pem
	rm -f root.ext
	rm -f root.pem
	rm -f eekey.pem
	rm -f localhost.csr
	rm -f localhost.ext
	rm -f localhost.pem

