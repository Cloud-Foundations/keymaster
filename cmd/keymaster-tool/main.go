package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"os"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/Cloud-Foundations/Dominator/lib/log/cmdlogger"
	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/certgen"
)

var (
	app         = kingpin.New("keyutil", "Tooling for puresigner2 secret management")
	debug       = app.Flag("debug", "Enable debug mode.").Bool()
	inSecretARN = app.Flag("secret-arn", "Location of secret to use").String()
	inAWSRegion = app.Flag("aws-region", "AWS region for secret").Default("us-west-2").String()

	generateCmd = app.Command("generate-new", "Generate a new keypair and encrypt")
	keyTypeIn   = generateCmd.Flag("type", "Type of Key (ed25519 | rsa)").Default("ed25519").String()

	printPublicCmd        = app.Command("printPublic", "Verify EMS secret")
	printPublicFilenameIn = printPublicCmd.Flag("inFilename", "File to Read").Required().String()
	printFormat           = printPublicCmd.Flag("printFormat", "format to use pem|ssh").Default("pem").String()
)

const rsaBits = 3072

func getPasswordFromConsole() ([]byte, error) {
	fmt.Printf("Passphrase for key ")
	return gopass.GetPasswd()
}

func getPassphraseFromARN(secretArn string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func getPassPhrase(secretArn string) ([]byte, error) {
	if secretArn != "" {
		return getPassphraseFromARN(secretArn)
	}
	return getPasswordFromConsole()

}

func armoredEncryptPrivateKey(privateKey interface{}, passphrase []byte) ([]byte, error) {
	encryptionType := "PGP MESSAGE"
	armoredBuf := new(bytes.Buffer)
	armoredWriter, err := armor.Encode(armoredBuf, encryptionType, nil)
	if err != nil {
		return nil, err
	}
	var plaintextWriter io.WriteCloser
	plaintextWriter, err = openpgp.SymmetricallyEncrypt(armoredWriter,
		passphrase, nil, nil)
	if err != nil {
		return nil, err
	}
	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	privateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derPrivateKey,
	}
	if err := pem.Encode(plaintextWriter, privateKeyPEM); err != nil {
		return nil, err
	}
	if err := plaintextWriter.Close(); err != nil {
		return nil, err
	}
	if err := armoredWriter.Close(); err != nil {
		return nil, err
	}
	return armoredBuf.Bytes(), nil
}

func generateNewKeyPair(passPhrase []byte, keyType string, outWriter io.Writer, logger log.DebugLogger) error {
	var privateKey crypto.Signer
	var err error
	switch keyType {
	case "ed25519":
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
	case "rsa":
		privateKey, err = rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("bad key type")
	}
	armoredBytes, err := armoredEncryptPrivateKey(privateKey, passPhrase)
	if err != nil {
		return err
	}
	_, err = outWriter.Write(armoredBytes)

	return err
}

func pgpDecryptFileData(cipherText []byte, password []byte) ([]byte, error) {
	decbuf := bytes.NewBuffer(cipherText)
	armorBlock, err := armor.Decode(decbuf)
	if err != nil {
		return nil, fmt.Errorf("cannot decode armored file")
	}
	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		// If the given passphrase isn't correct, the function will be called
		// again, forever.
		// This method will fail fast.
		// Ref: https://godoc.org/golang.org/x/crypto/openpgp#PromptFunction
		if failed {
			return nil, fmt.Errorf("decryption failed")
		}
		failed = true
		return password, nil
	}
	md, err := openpgp.ReadMessage(armorBlock.Body, nil, prompt, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt key: %s", err)
	}
	return ioutil.ReadAll(md.UnverifiedBody)
}

func decryptDecodeArmoredPrivateKey(cipherText []byte, passPhrase []byte) (crypto.Signer, error) {
	plaintext, err := pgpDecryptFileData(cipherText, passPhrase)
	if err != nil {
		return nil, err
	}
	return certgen.GetSignerFromPEMBytes(plaintext)
}

//copied from https://golang.org/src/crypto/tls/generate_cert.go
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

func printPublicKey(passPhrase []byte, inFilename string, outWriter io.Writer, logger log.DebugLogger) error {
	inFile, err := os.Open(inFilename) // For read access.
	if err != nil {
		return err
	}
	defer inFile.Close()
	cipherText, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}
	signer, err := decryptDecodeArmoredPrivateKey(passPhrase, cipherText)
	if err != nil {
		return err
	}
	pubKey := publicKey(signer)
	if pubKey == nil {
		return fmt.Errorf("Invalid private key type")
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}
	_, err = outWriter.Write(pubKeyBytes)

	return err
}

func main() {

	logger := cmdlogger.New()
	//var err error
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	// Register user
	case generateCmd.FullCommand():
		passPhrase, err := getPassPhrase(*inSecretARN)
		if err != nil {
			stdlog.Fatalf("Error: %s", err)
		}
		err = generateNewKeyPair(passPhrase, *keyTypeIn, os.Stdout, logger)
		if err != nil {
			stdlog.Fatalf("Error: %s", err)
		}
	case printPublicCmd.FullCommand():
		passPhrase, err := getPassPhrase(*inSecretARN)
		if err != nil {
			stdlog.Fatalf("Error: %s", err)
		}
		err = printPublicKey(passPhrase, *printPublicFilenameIn, os.Stdout, logger)
		if err != nil {
			stdlog.Fatalf("Error: %s", err)
		}

	}

}
