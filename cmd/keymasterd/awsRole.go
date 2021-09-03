package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/certgen"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

type parsedArnType struct {
	parsedArn arn.ARN
	role      string
}

func getCallerIdentity(key, secret, token string) (*parsedArnType, error) {
	creds := credentials.NewStaticCredentials(key, secret, token)
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Credentials: creds}})
	if err != nil {
		return nil, err
	}
	stsSvc := sts.New(sess)
	output, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	parsedArn, err := arn.Parse(*output.Arn)
	if err != nil {
		return nil, err
	}
	parsedArn.Region = ""
	parsedArn.Service = "iam"
	splitResource := strings.Split(parsedArn.Resource, "/")
	if len(splitResource) > 1 && splitResource[0] == "assumed-role" {
		parsedArn.Resource = "role/" + splitResource[1]
	}
	return &parsedArnType{
		parsedArn: parsedArn,
		role:      splitResource[1],
	}, nil
}

func (state *RuntimeState) requestAwsRoleCertificateHandler(
	w http.ResponseWriter, r *http.Request) {
	state.logger.Debugln(1, "Entered requestAwsRoleCertificateHandler()")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	if r.Method != "POST" {
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	// First extract and validate AWS credentials.
	key := r.Header.Get("aws-access-key-id")
	secret := r.Header.Get("aws-secret-access-key")
	token := r.Header.Get("aws-session-token")
	if key == "" || secret == "" || token == "" {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"missing credential data")
		return
	}
	callerArn, err := getCallerIdentity(key, secret, token)
	if err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"cannot identify credentials")
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error reading body")
		return
	}
	// Now extract the public key PEM data.
	block, _ := pem.Decode(body)
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
	strong, err := certgen.ValidatePublicKeyStrength(pub)
	if err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"cannot check key strength")
		return
	}
	if !strong {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "key too weak")
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
	callerArn *parsedArnType) ([]byte, error) {
	subject := pkix.Name{
		CommonName: fmt.Sprintf("aws:iam:%s:%s",
			callerArn.parsedArn.AccountID, callerArn.role),
		Organization: []string{"keymaster"},
	}
	arnUrl, err := url.Parse(callerArn.parsedArn.String())
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
