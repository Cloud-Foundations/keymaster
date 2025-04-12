package yksigner

import (
	"crypto"
	"io"
	"sync"

	"github.com/cviecco/piv-go/v2/piv"
)

type YkSigner struct {
	yk        *piv.YubiKey
	ykSerial  uint32
	pivPIN    string
	publicKey crypto.PublicKey
	signer    crypto.Signer
	ykMutex   sync.Mutex
}

// NewYkPivSigner connects to a yubikey in PIV mode for generating a crypto.Signer
// interface.
// serial is the yubikey serial. If the special value 0 is used then is assumed
// that the first yubikey found will be used.
// pivPIN is the
func NewYkPivSigner(serial uint32, pivPIN string, pub crypto.PublicKey) (*YkSigner, error) {
	return newYkPivSigner(serial, pivPIN, pub)
}

func (ks *YkSigner) Public() crypto.PublicKey {
	return ks.public()
}

func (ks *YkSigner) Sign(reader io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ks.sign(reader, message, opts)
}

func (ks *YkSigner) Close() {
	if ks.yk != nil {
		ks.yk.Close()
	}
}
