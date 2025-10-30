package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/howeyc/gopass"
)

const rsaBits = 3072

func getPasswordFromConsole() ([]byte, error) {
	fmt.Fprintf(os.Stderr, "Passphrase for key ")
	return gopass.GetPasswd()
}

func getPassphraseFromAWS(awsSecretId string, awsRegion string) ([]byte, error) {
	svc := secretsmanager.New(session.New(),
		aws.NewConfig().WithRegion(awsRegion))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(awsSecretId),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}
	result, err := svc.GetSecretValue(input)
	if err != nil {
		return nil, err
	}
	return []byte(*result.SecretString), nil

}

func getPassPhrase(secretArn string, awsRegion string) ([]byte, error) {
	if secretArn != "" {
		return getPassphraseFromAWS(secretArn, awsRegion)
	}
	return getPasswordFromConsole()

}

// copied from https://golang.org/src/crypto/tls/generate_cert.go
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	case *ed25519.PrivateKey:
		return k.Public().(*ed25519.PublicKey)
	default:
		return nil
	}
}
