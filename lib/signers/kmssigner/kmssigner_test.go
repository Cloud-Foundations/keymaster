package kmssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// This is an insecure, test-only key from RFC 9500, Section 2.1.
const testRSAKey = `-----BEGIN RSA TESTING KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
-----END RSA TESTING KEY-----`

type kmsClientMock struct {
	signer crypto.Signer
}

func (mock *kmsClientMock) GetPublicKey(ctx context.Context,
	input *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	var resp kms.GetPublicKeyOutput
	// we may want to do eventualy do differently for RSA
	var err error
	switch v := mock.signer.Public().(type) {
	case *rsa.PublicKey:
		resp.PublicKey = x509.MarshalPKCS1PublicKey(v)
	default:
		resp.PublicKey, err = x509.MarshalPKCS8PrivateKey(mock.signer.Public())
	}
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (mock *kmsClientMock) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	var resp kms.SignOutput
	var signOpts crypto.SignerOpts
	switch params.SigningAlgorithm {
	case types.SigningAlgorithmSpecEcdsaSha256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		signOpts = crypto.SHA256
	case types.SigningAlgorithmSpecEcdsaSha384:
		signOpts = crypto.SHA384
	default:
		return nil, fmt.Errorf("enhance mock for better signeture types")
	}
	signature, err := mock.signer.Sign(rand.Reader, params.Message, signOpts)
	if err != nil {
		return nil, err
	}
	resp.Signature = signature
	return &resp, nil
}

func TestGetSigningAlgorithmSuccess(t *testing.T) {
	hashAlgos := []crypto.SignerOpts{crypto.SHA256, crypto.SHA384}
	//p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	expectedECDSASignalgos := map[crypto.SignerOpts]types.SigningAlgorithmSpec{
		crypto.SHA256: types.SigningAlgorithmSpecEcdsaSha256,
		crypto.SHA384: types.SigningAlgorithmSpecEcdsaSha384,
	}
	for _, hash := range hashAlgos {
		algoType, err := getSigningAlgorithm(p384Key.Public(), hash)
		if err != nil {
			t.Fatal(err)
		}
		if algoType != expectedECDSASignalgos[hash] {
			t.Fatal("unexpected value")
		}
	}

	block, _ := pem.Decode([]byte(strings.ReplaceAll(testRSAKey, "TESTING KEY", "PRIVATE KEY")))
	testRSA2048, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, hash := range hashAlgos {
		_, err = getSigningAlgorithm(testRSA2048.Public(), hash)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPreloadKey(t *testing.T) {
	var mClient kmsClientMock
	var err error
	block, _ := pem.Decode([]byte(strings.ReplaceAll(testRSAKey, "TESTING KEY", "PRIVATE KEY")))
	mClient.signer, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var kmsSigner KmsSigner
	kmsSigner.client = &mClient
	kmsSigner.keyID = "1"

	ctx, cancel := defaultContext()
	defer cancel()
	err = kmsSigner.preloadKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// TODO do again with an ECDSA key
}

func TestSign(t *testing.T) {
	var mClient kmsClientMock
	var err error
	block, _ := pem.Decode([]byte(strings.ReplaceAll(testRSAKey, "TESTING KEY", "PRIVATE KEY")))
	mClient.signer, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var kmsSigner KmsSigner
	kmsSigner.client = &mClient
	kmsSigner.keyID = "1"

	ctx, cancel := defaultContext()
	defer cancel()
	err = kmsSigner.preloadKey(ctx)
	if err != nil {
		t.Fatal(err)
	}

	message := "hello world"
	// TODO make the test more generic to test ecsda
	digest := sha256.Sum256([]byte(message))
	_, err = kmsSigner.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
}
