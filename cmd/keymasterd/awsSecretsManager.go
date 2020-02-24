package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

var (
	awsSecretsManagerLock                sync.Mutex
	awsSecretsManagerMetadataClient      *ec2metadata.EC2Metadata
	awsSecretsManagerMetadataClientError error
)

func getMetadataClient() (*ec2metadata.EC2Metadata, error) {
	awsSecretsManagerLock.Lock()
	defer awsSecretsManagerLock.Unlock()
	if awsSecretsManagerMetadataClient != nil {
		return awsSecretsManagerMetadataClient, nil
	}
	if awsSecretsManagerMetadataClientError != nil {
		return nil, awsSecretsManagerMetadataClientError
	}
	metadataClient := ec2metadata.New(session.New())
	if !metadataClient.Available() {
		awsSecretsManagerMetadataClientError = errors.New(
			"not running on AWS or metadata is not available")
		return nil, awsSecretsManagerMetadataClientError
	}
	awsSecretsManagerMetadataClient = metadataClient
	return awsSecretsManagerMetadataClient, nil
}

func getAwsSecret(metadataClient *ec2metadata.EC2Metadata,
	secretId string) (map[string]string, error) {
	var region string
	if arn, err := arn.Parse(secretId); err == nil {
		region = arn.Region
	} else {
		region, err = metadataClient.Region()
		if err != nil {
			return nil, err
		}
	}
	awsSession, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating session: %s", err)
	}
	if awsSession == nil {
		return nil, errors.New("awsSession == nil")
	}
	awsService := secretsmanager.New(awsSession)
	input := secretsmanager.GetSecretValueInput{SecretId: aws.String(secretId)}
	output, err := awsService.GetSecretValue(&input)
	if err != nil {
		return nil,
			fmt.Errorf("error calling secretsmanager:GetSecretValue: %s", err)
	}
	if output.SecretString == nil {
		return nil, errors.New("no SecretString in secret")
	}
	secret := []byte(*output.SecretString)
	var secrets map[string]string
	if err := json.Unmarshal(secret, &secrets); err != nil {
		return nil, fmt.Errorf("error unmarshaling secret: %s", err)
	}
	return secrets, nil
}
