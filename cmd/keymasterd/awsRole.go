package main

import (
	"context"
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
	"strconv"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/certgen"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	awsAccountListInterval = time.Minute * 5
)

type assumeRoleCredentialsProvider struct {
	credentials aws.Credentials
	roleArn     *string
	stsClient   *sts.Client
}

type getCallerIdentityResult struct {
	Arn string
}

type getCallerIdentityResponse struct {
	GetCallerIdentityResult getCallerIdentityResult
}

type parsedArnType struct {
	parsedArn arn.ARN
	role      string
}

func awsListAccounts(ctx context.Context, orgClient *organizations.Client) (
	map[string]struct{}, error) {
	output, err := orgClient.ListAccounts(ctx,
		&organizations.ListAccountsInput{})
	if err != nil {
		return nil, err
	}
	list := make(map[string]struct{}, len(output.Accounts))
	for _, account := range output.Accounts {
		list[*account.Id] = struct{}{}
	}
	return list, nil
}

func getCallerIdentity(header http.Header,
	validator func(presignedUrl string) (*url.URL, error)) (
	*parsedArnType, error) {
	claimedArn := header.Get("claimed-arn")
	presignedMethod := header.Get("presigned-method")
	presignedUrl := header.Get("presigned-url")
	if claimedArn == "" || presignedUrl == "" || presignedMethod == "" {
		return nil, fmt.Errorf("missing presigned request data")
	}
	validatedUrl, err := validator(presignedUrl)
	if err != nil {
		return nil, err
	}
	presignedUrl = validatedUrl.String()
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
	// Normalise to the actual role ARN, rather than an ARN showing how the
	// credentials were obtained. This mirrors the way AWS policy documents are
	// written.
	parsedArn.Region = ""
	parsedArn.Service = "iam"
	splitResource := strings.Split(parsedArn.Resource, "/")
	if len(splitResource) < 2 || splitResource[0] != "assumed-role" {
		return nil, fmt.Errorf("invalid resource: %s", parsedArn.Resource)
	}
	parsedArn.Resource = "role/" + splitResource[1]
	if parsedArn.String() != claimedArn {
		return nil, fmt.Errorf("validated ARN: %s != claimed ARN: %s",
			parsedArn.String(), claimedArn)
	}
	return &parsedArnType{
		parsedArn: parsedArn,
		role:      splitResource[1],
	}, nil
}

// validateStsPresignedUrl will validate if the URL is a valid AWS URL.
// It returns the parsed, validated URL so that the caller can rebuild the URL
// (to hopefully silence code security scanners which are dumb).
func validateStsPresignedUrl(presignedUrl string) (*url.URL, error) {
	parsedPresignedUrl, err := url.Parse(presignedUrl)
	if err != nil {
		return nil, err
	}
	if parsedPresignedUrl.Scheme != "https" {
		return nil, fmt.Errorf("invalid scheme: %s", parsedPresignedUrl.Scheme)
	}
	if parsedPresignedUrl.Path != "/" {
		return nil, fmt.Errorf("invalid path: %s", parsedPresignedUrl.Path)
	}
	if !strings.HasPrefix(parsedPresignedUrl.RawQuery,
		"Action=GetCallerIdentity&") {
		return nil,
			fmt.Errorf("invalid action: %s", parsedPresignedUrl.RawQuery)
	}
	splitHost := strings.Split(parsedPresignedUrl.Host, ".")
	if len(splitHost) != 4 ||
		splitHost[0] != "sts" ||
		splitHost[2] != "amazonaws" ||
		splitHost[3] != "com" {
		return nil, fmt.Errorf("malformed presigned URL host")
	}
	return parsedPresignedUrl, nil
}

func (p *assumeRoleCredentialsProvider) Retrieve(ctx context.Context) (
	aws.Credentials, error) {
	if time.Until(p.credentials.Expires) > time.Minute {
		return p.credentials, nil
	}
	output, err := p.stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         p.roleArn,
		RoleSessionName: aws.String("keymaster"),
	})
	if err != nil {
		return aws.Credentials{}, err
	}
	p.credentials = aws.Credentials{
		AccessKeyID:     *output.Credentials.AccessKeyId,
		CanExpire:       true,
		Expires:         *output.Credentials.Expiration,
		SecretAccessKey: *output.Credentials.SecretAccessKey,
		SessionToken:    *output.Credentials.SessionToken,
	}
	return p.credentials, nil
}

func (state *RuntimeState) checkAwsRolesEnabled() bool {
	if len(state.Config.AwsCerts.AllowedAccounts) > 0 {
		return true
	}
	if state.Config.AwsCerts.ListAccountsRole != "" {
		return true
	}
	return false
}

func (state *RuntimeState) configureAwsRoles() error {
	if len(state.Config.AwsCerts.AllowedAccounts) > 0 {
		state.Config.AwsCerts.allowedAccounts =
			make(map[string]struct{})
		for _, id := range state.Config.AwsCerts.AllowedAccounts {
			if _, err := strconv.ParseUint(id, 10, 64); err != nil {
				return fmt.Errorf("accountID: %s is not a number", id)
			}
			state.Config.AwsCerts.allowedAccounts[id] = struct{}{}
		}
	}
	if state.Config.AwsCerts.ListAccountsRole != "" {
		ctx := context.TODO()
		awsConfig, err := awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithEC2IMDSRegion())
		if err != nil {
			return err
		}
		credsProvider := &assumeRoleCredentialsProvider{
			roleArn:   aws.String(state.Config.AwsCerts.ListAccountsRole),
			stsClient: sts.NewFromConfig(awsConfig),
		}
		awsConfig, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithEC2IMDSRegion(),
			awsconfig.WithCredentialsProvider(credsProvider))
		if err != nil {
			return err
		}
		orgClient := organizations.NewFromConfig(awsConfig)
		state.Config.AwsCerts.organisationAccounts, err =
			awsListAccounts(ctx, orgClient)
		if err != nil {
			return err
		}
		go state.refreshAwsAccounts(ctx, orgClient)
	}
	return nil
}

func (state *RuntimeState) checkAwsAccountAllowed(accountId string) bool {
	if _, ok := state.Config.AwsCerts.allowedAccounts[accountId]; ok {
		return true
	}
	if _, ok := state.Config.AwsCerts.organisationAccounts[accountId]; ok {
		return true
	}
	if _, ok := state.Config.AwsCerts.allowedAccounts["*"]; ok {
		return true
	}
	return false
}

func (state *RuntimeState) refreshAwsAccounts(ctx context.Context,
	orgClient *organizations.Client) {
	for {
		time.Sleep(awsAccountListInterval)
		if list, err := awsListAccounts(ctx, orgClient); err != nil {
			state.logger.Println(err)
		} else {
			state.Config.AwsCerts.organisationAccounts = list
		}
	}
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
	callerArn, err := getCallerIdentity(r.Header, validateStsPresignedUrl)
	if err != nil {
		state.logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"verification request failed")
		return
	}
	if !state.checkAwsAccountAllowed(callerArn.parsedArn.AccountID) {
		state.logger.Printf("AWS account: %s not allowed\n",
			callerArn.parsedArn.AccountID)
		state.writeFailureResponse(w, r, http.StatusUnauthorized,
			"AWS account not allowed")
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
