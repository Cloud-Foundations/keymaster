package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
)

const (
	awsAccountListInterval = time.Minute * 5
)

type assumeRoleCredentialsProvider struct {
	credentials aws.Credentials
	roleArn     *string
	stsClient   *sts.Client
}

func awsListAccounts(ctx context.Context, orgClient *organizations.Client) (
	map[string]struct{}, error) {
	list := make(map[string]struct{})
	var nextToken *string
	for {
		output, err := orgClient.ListAccounts(ctx,
			&organizations.ListAccountsInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		for _, account := range output.Accounts {
			list[*account.Id] = struct{}{}
		}
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	return list, nil
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
			if id != "*" {
				if _, err := strconv.ParseUint(id, 10, 64); err != nil {
					return fmt.Errorf("accountID: %s is not a number", id)
				}
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
		state.logger.Printf("Discovered %d accounts in AWS Organisation\n",
			len(state.Config.AwsCerts.organisationAccounts))
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
			oldLength := len(state.Config.AwsCerts.organisationAccounts)
			state.Config.AwsCerts.organisationAccounts = list
			if len(list) != oldLength {
				state.logger.Printf(
					"Discovered %d accounts in AWS Organisation, was %d\n",
					len(list), oldLength)
			}
		}
	}
}

func (state *RuntimeState) requestAwsRoleCertificateHandler(
	w http.ResponseWriter, r *http.Request) {
	state.logger.Debugln(1, "Entered requestAwsRoleCertificateHandler()")
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	cert := state.awsCertIssuer.RequestHandler(w, r)
	if cert != nil {
		w.(*instrumentedwriter.LoggingWriter).SetUsername(
			cert.Subject.CommonName)
	}
}

// Returns signed certificate DER.
func (state *RuntimeState) generateRoleCert(template *x509.Certificate,
	publicKey interface{}) ([]byte, error) {
	strong, err := certgen.ValidatePublicKeyStrength(publicKey)
	if err != nil {
		return nil, err
	}
	if !strong {
		return nil, fmt.Errorf("key too weak")
	}
	signer, caCertDer, err := state.getSignerX509CAForPublic(publicKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caCertDer)
	if err != nil {
		return nil, err
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert,
		publicKey, signer)
	if err != nil {
		return nil, err
	}
	metricLogCertDuration("x509", "granted",
		float64(time.Until(template.NotAfter).Seconds()))
	go func(username string, certType string) {
		metricsMutex.Lock()
		defer metricsMutex.Unlock()
		certGenCounter.WithLabelValues(username, certType).Inc()
	}(template.Subject.CommonName, "x509")
	return certDER, nil
}
