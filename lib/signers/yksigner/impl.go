package yksigner

import (
	"crypto"
	"fmt"
	"io"
	"strings"

	"github.com/cviecco/piv-go/v2/piv"
)

func newYkPivSigner(serial uint32, pivPIN string, pub crypto.PublicKey) (*YkSigner, error) {
	ks := YkSigner{
		ykSerial: serial,
		pivPIN:   pivPIN,
	}

	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if ks.yk, err = piv.Open(card); err != nil {
				return nil, fmt.Errorf("error opening yubikey err=%s", err)
			}
			ykSerial, err := ks.yk.Serial()
			if err != nil {
				return nil, err
			}
			if serial == 0 || serial == ykSerial {
				ks.ykSerial = ykSerial
				break
			}
			ks.yk.Close()
			ks.yk = nil
		}
	}
	if ks.yk == nil {
		return nil, fmt.Errorf("No yubikey found")
	}

	if pub == nil {
		cert, err := ks.yk.Attest(piv.SlotAuthentication)
		if err != nil {
			ks.yk.Close()
			return nil, err
		}
		pub = cert.PublicKey
	}
	ks.publicKey = pub
	auth := piv.KeyAuth{PIN: pivPIN}
	priv, err := ks.yk.PrivateKey(piv.SlotAuthentication, pub, auth)
	if err != nil {
		ks.yk.Close()
		return nil, fmt.Errorf("Error getting the key=%s", err)
	}
	switch signer := priv.(type) {
	case *piv.ECDSAPrivateKey:
		ks.signer = signer
		return &ks, nil
	case *piv.Ed25519Key:
		ks.signer = signer
		return &ks, nil
	case *piv.RSAkey:
		ks.signer = signer
		return &ks, nil
	default:
		ks.yk.Close()
		return nil, fmt.Errorf("cannot YK private key cannot be converted into signer")
	}
}

func (ks *YkSigner) public() crypto.PublicKey {
	return ks.publicKey
}

func (ks *YkSigner) sign(reader io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	ks.ykMutex.Lock()
	defer ks.ykMutex.Unlock()
	return ks.signer.Sign(reader, message, opts)
}
