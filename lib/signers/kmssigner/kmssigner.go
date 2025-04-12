package kmssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func newKmsSigner(cfg aws.Config, ctx context.Context, keyname string) (*KmsSigner, error) {
	client := kms.NewFromConfig(cfg)
	var ks KmsSigner
	ks.client = client
	ks.keyID = keyname
	err := ks.preloadKey(ctx)
	if err != nil {
		return nil, err
	}
	return &ks, nil
}

// assumes keyID is set
func (ks *KmsSigner) preloadKey(ctx context.Context) error {

	resp, err := ks.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &ks.keyID,
	})
	if err != nil {
		return err
	}
	ks.publicKey, err = x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		ks.publicKey, err = x509.ParsePKCS1PublicKey(resp.PublicKey)
		if err != nil {
			return fmt.Errorf("cannot decode key err=%s", err)
		}

	}
	return nil
}

func (ks *KmsSigner) public() crypto.PublicKey {
	return ks.publicKey
}

func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

func (ks *KmsSigner) sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, err := getSigningAlgorithm(ks.Public(), opts)
	if err != nil {
		return nil, err
	}
	messageType := types.MessageTypeRaw
	if opts.HashFunc() != 0 {
		messageType = types.MessageTypeDigest
	}

	req := &kms.SignInput{
		KeyId:            &ks.keyID,
		SigningAlgorithm: alg,
		Message:          message,
		MessageType:      messageType,
	}

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := ks.client.Sign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("awskms Sign failed err=%s", err)
	}

	return resp.Signature, nil
}

func getSigningAlgorithm(key crypto.PublicKey, opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		_, isPSS := opts.(*rsa.PSSOptions)
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha256, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha384, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha512, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		default:
			return "", fmt.Errorf("unsupported hash function %v", h)
		}
	case *ecdsa.PublicKey:
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			//log.Printf("getSigningAlgorithm hash opts selecting sha256")
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			//log.Printf("getSigningAlgorithm hash opts selecting sha384")
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return "", fmt.Errorf("unsupported hash function %v", h)
		}
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
}
