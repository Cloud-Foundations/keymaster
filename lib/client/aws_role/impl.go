package aws_role

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/Cloud-Foundations/keymaster/lib/paths"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func parseArn(arnString string) (*arn.ARN, error) {
	parsedArn, err := arn.Parse(arnString)
	if err != nil {
		return nil, err
	}
	switch parsedArn.Service {
	case "iam", "sts":
	default:
		return nil, fmt.Errorf("unsupported service: %s", parsedArn.Service)
	}
	splitResource := strings.Split(parsedArn.Resource, "/")
	if len(splitResource) < 2 || splitResource[0] != "assumed-role" {
		return nil, fmt.Errorf("invalid resource: %s", parsedArn.Resource)
	}
	parsedArn.Service = "iam"
	parsedArn.Resource = "role/" + splitResource[1]
	return &parsedArn, nil
}

// Returns certificate PEM block.
func (p Params) getRoleCertificate() ([]byte, error) {
	if p.KeymasterServer == "" {
		return nil, fmt.Errorf("no keymaster server specified")
	}
	if p.Logger == nil {
		return nil, fmt.Errorf("no logger specified")
	}
	if p.Context == nil {
		p.Context = context.TODO()
	}
	if p.HttpClient == nil {
		p.HttpClient = http.DefaultClient
	}
	if p.Signer == nil {
		signer, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		p.Signer = signer
		p.KeyType = "RSA"
	}
	if p.KeyType != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", p.KeyType)
	}
	derPubKey, err := x509.MarshalPKIXPublicKey(p.Signer.Public())
	if err != nil {
		return nil, err
	}
	p.derPubKey = derPubKey
	awsConfig, err := config.LoadDefaultConfig(p.Context)
	if err != nil {
		return nil, err
	}
	p.pemPubKey = pem.EncodeToMemory(&pem.Block{
		Bytes: p.derPubKey,
		Type:  "PUBLIC KEY",
	})
	stsClient := sts.NewFromConfig(awsConfig)
	idOutput, err := stsClient.GetCallerIdentity(p.Context,
		&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	p.Logger.Debugf(0, "Account: %s, ARN: %s, UserId: %s\n",
		*idOutput.Account, *idOutput.Arn, *idOutput.UserId)
	parsedArn, err := parseArn(*idOutput.Arn)
	if err != nil {
		return nil, err
	}
	assumeOutput, err := stsClient.AssumeRole(p.Context, &sts.AssumeRoleInput{
		DurationSeconds: aws.Int32(900),
		RoleArn:         aws.String(parsedArn.String()),
		RoleSessionName: aws.String("identity-verifier"),
	})
	if err != nil {
		p.Logger.Println(err)
		creds, err := awsConfig.Credentials.Retrieve(p.Context)
		if err != nil {
			return nil, err
		}
		p.Logger.Println(
			"unable to assume limited role, passing primary credentials")
		return p.requestCertificate(creds.AccessKeyID, creds.SecretAccessKey,
			creds.SessionToken)
	}
	return p.requestCertificate(*assumeOutput.Credentials.AccessKeyId,
		*assumeOutput.Credentials.SecretAccessKey,
		*assumeOutput.Credentials.SessionToken)
}

// Returns certificate PEM block.
func (p *Params) requestCertificate(key, secret, token string) ([]byte, error) {
	hostPath := p.KeymasterServer + paths.RequestAwsRoleCertificatePath
	body := &bytes.Buffer{}
	fmt.Fprintf(body, "aws_access_key_id     = %s\n", key)
	fmt.Fprintf(body, "aws_secret_access_key = %s\n", secret)
	fmt.Fprintf(body, "aws_session_token     = %s\n", token)
	body.Write(p.pemPubKey)
	req, err := http.NewRequestWithContext(p.Context, "GET", hostPath, body)
	if err != nil {
		return nil, err
	}
	resp, err := p.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got error from call %s, url='%s'\n",
			resp.Status, hostPath)
	}
	return ioutil.ReadAll(resp.Body)
}
