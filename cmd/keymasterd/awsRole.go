package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

func getCallerIdentity(key, secret, token string) (string, error) {
	creds := credentials.NewStaticCredentials(key, secret, token)
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Credentials: creds}})
	if err != nil {
		return "", err
	}
	stsSvc := sts.New(sess)
	output, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	parsedArn, err := arn.Parse(*output.Arn)
	if err != nil {
		return "", err
	}
	parsedArn.Region = ""
	parsedArn.Service = "iam"
	splitResource := strings.Split(parsedArn.Resource, "/")
	if len(splitResource) > 1 && splitResource[0] == "assumed-role" {
		parsedArn.Resource = "role/" + splitResource[1]
	}
	return parsedArn.String(), nil
}

func (state *RuntimeState) requestAwsRoleCertificateHandler(
	w http.ResponseWriter, r *http.Request) {
	state.logger.Debugln(1, "Entered requestAwsRoleCertificateHandler()")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error reading body")
		return
	}
	// First extract the AWS credentials.
	var key, secret, token string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		splitLine := strings.SplitN(scanner.Text(), "=", 2)
		if len(splitLine) != 2 {
			continue
		}
		value := strings.TrimSpace(splitLine[1])
		switch strings.ToLower(strings.TrimSpace(splitLine[0])) {
		case "aws_access_key_id":
			key = value
		case "aws_secret_access_key":
			secret = value
		case "aws_session_token":
			token = value
		}
	}
	if err := scanner.Err(); err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"error parsing body")
		return
	}
	// Now extract the public key PEM data.
	index := bytes.Index(body, []byte("-----BEGIN"))
	if index < 1 {
		state.logger.Println("did not find start of PEM block")
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"missing PEM block")
		return
	}
	block, _ := pem.Decode(body[index:])
	if block == nil {
		state.logger.Println("unable to decode PEM block")
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"invalid PEM block")
		return
	}
	if block.Type != "PUBLIC KEY" {
		state.logger.Printf("unsupport PEM type: %s\n", block.Type)
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"unsupported PEM type")
		return
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "invalid DER")
		return
	}
	callerArn, err := getCallerIdentity(key, secret, token)
	if err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"cannot identify credentials")
		return
	}
	certDER, err := state.generateRoleCert(pub, callerArn)
	if err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"cannot generate certificate")
		return
	}
	pem.Encode(w, &pem.Block{Bytes: certDER, Type: "CERTIFICATE"})
}

// Returns certificate DER.
func (state *RuntimeState) generateRoleCert(publicKey interface{},
	callerArn string) ([]byte, error) {
	subject := pkix.Name{
		CommonName:   "AWS_ARN",
		Organization: []string{"keymaster"},
	}
	arnUrl, err := url.Parse(callerArn)
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{arnUrl},
	}
	caCert, err := x509.ParseCertificate(state.caCertDer)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificate(rand.Reader, &template, caCert, publicKey,
		state.Signer)
}
