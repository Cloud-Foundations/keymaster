package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/certgen"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

type parsedArnType struct {
	parsedArn arn.ARN
	role      string
}

type getCallerIdentityResult struct {
	Arn string
}

type getCallerIdentityResponse struct {
	GetCallerIdentityResult getCallerIdentityResult
}

func getCallerIdentity(presignedUrl string,
	presignedMethod string) (*parsedArnType, error) {
	parsedPresignedUrl, err := url.Parse(presignedUrl)
	if err != nil {
		return nil, err
	}
	splitHost := strings.Split(parsedPresignedUrl.Host, ".")
	if len(splitHost) != 4 ||
		splitHost[0] != "sts" ||
		splitHost[2] != "amazonaws" ||
		splitHost[3] != "com" {
		return nil, fmt.Errorf("malformed presigned URL host")
	}
	validateReq, err := http.NewRequest(presignedMethod, presignedUrl, nil)
	if err != nil {
		return nil, err
	}
	validateResp, err := http.DefaultClient.Do(validateReq)
	if err != nil {
		return nil, err
	}
	defer validateResp.Body.Close()
	if validateResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verification request failed")
	}
	body, err := ioutil.ReadAll(validateResp.Body)
	if err != nil {
		return nil, err
	}
	var callerIdentity getCallerIdentityResponse
	if err := xml.Unmarshal(body, &callerIdentity); err != nil {
		return nil, err
	}
	parsedArn, err := arn.Parse(callerIdentity.GetCallerIdentityResult.Arn)
	if err != nil {
		return nil, err
	}
	parsedArn.Region = ""
	parsedArn.Service = "iam"
	splitResource := strings.Split(parsedArn.Resource, "/")
	if len(splitResource) < 2 || splitResource[0] != "assumed-role" {
		return nil, fmt.Errorf("invalid resource: %s", parsedArn.Resource)
	}
	parsedArn.Resource = "role/" + splitResource[1]
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
	// First extract and validate AWS credentials claim.
	claimedArn := r.Header.Get("claimed-arn")
	presignedUrl := r.Header.Get("presigned-url")
	presignedMethod := r.Header.Get("presigned-method")
	if claimedArn == "" || presignedUrl == "" || presignedMethod == "" {
		state.writeFailureResponse(w, r, http.StatusBadRequest,
			"missing presigned request data")
		return
	}
	callerArn, err := getCallerIdentity(presignedUrl, presignedMethod)
	if err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"verification request failed")
		return
	}
	if callerArn.parsedArn.String() != claimedArn {
		state.logger.Printf("validated ARN: %s != claimed ARN: %s\n",
			callerArn.parsedArn.String(), claimedArn)
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"ARN claim does not match")
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
