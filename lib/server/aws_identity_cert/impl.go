package aws_identity_cert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	presignc "github.com/Cloud-Foundations/golib/pkg/awsutil/presignauth/caller"
	"github.com/Cloud-Foundations/golib/pkg/log/nulllogger"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

func defaultFailureWriter(w http.ResponseWriter, r *http.Request,
	errorString string, code int) {
	http.Error(w, errorString, code)
}

func getCallerIdentity(header http.Header,
	presignCallerClient presignc.Caller) (arn.ARN, error) {
	claimedArn := html.EscapeString(header.Get("claimed-arn"))
	presignedMethod := header.Get("presigned-method")
	presignedUrl := header.Get("presigned-url")
	if claimedArn == "" || presignedUrl == "" || presignedMethod == "" {
		return arn.ARN{}, fmt.Errorf("missing presigned request data")
	}
	parsedArn, err := presignCallerClient.GetCallerIdentity(nil,
		presignedMethod, presignedUrl)
	if err != nil {
		return arn.ARN{}, err
	}
	if parsedArn.String() != claimedArn {
		return arn.ARN{}, fmt.Errorf("validated ARN: %s != claimed ARN: %s",
			parsedArn.String(), claimedArn)
	}
	return parsedArn, nil
}

func makeCertificateTemplate(callerArn arn.ARN) (*x509.Certificate, error) {
	if !strings.HasPrefix(callerArn.Resource, "role/") {
		return nil, fmt.Errorf("invalid resource: %s", callerArn.Resource)
	}
	commonName := roleCommonName(callerArn)
	subject := pkix.Name{
		CommonName:   commonName,
		Organization: []string{"keymaster"},
	}
	arnUrl, err := url.Parse(callerArn.String())
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{arnUrl},
	}, nil
}

func newIssuer(params Params) (*Issuer, error) {
	if params.AccountIdValidator == nil {
		params.AccountIdValidator = nullAccountIdValidator
	}
	if params.FailureWriter == nil {
		params.FailureWriter = defaultFailureWriter
	}
	if params.Logger == nil {
		params.Logger = nulllogger.New()
	}
	presignCallerClient, err := presignc.New(presignc.Params{
		HttpClient: params.HttpClient,
		Logger:     params.Logger,
	})
	if err != nil {
		return nil, err
	}
	return &Issuer{
		presignCallerClient: presignCallerClient,
		params:              params,
	}, nil
}

func nullAccountIdValidator(accountId string) bool {
	return true
}

func nullCertificateModifier(cert *x509.Certificate) error {
	return nil
}

func roleCommonName(roleArn arn.ARN) string {
	return fmt.Sprintf("aws:iam:%s:%s", roleArn.AccountID, roleArn.Resource[5:])
}

func (i *Issuer) requestHandler(w http.ResponseWriter,
	r *http.Request) *x509.Certificate {
	if r.Method != "POST" {
		i.params.FailureWriter(w, r, "", http.StatusMethodNotAllowed)
		return nil
	}
	// First extract and validate AWS credentials claim.
	callerArn, err := getCallerIdentity(r.Header, i.presignCallerClient)
	if err != nil {
		i.params.Logger.Println(err)
		i.params.FailureWriter(w, r, "verification request failed",
			http.StatusUnauthorized)
		return nil
	}
	if !i.params.AccountIdValidator(callerArn.AccountID) {
		i.params.Logger.Printf("AWS account: %s not allowed\n",
			callerArn.AccountID)
		i.params.FailureWriter(w, r, "AWS account not allowed",
			http.StatusUnauthorized)
		return nil
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		i.params.Logger.Println(err)
		i.params.FailureWriter(w, r, "error reading body",
			http.StatusInternalServerError)
		return nil
	}
	// Now extract the public key PEM data.
	block, _ := pem.Decode(body)
	if block == nil {
		i.params.Logger.Println("unable to decode PEM block")
		i.params.FailureWriter(w, r, "invalid PEM block", http.StatusBadRequest)
		return nil
	}
	if block.Type != "PUBLIC KEY" {
		i.params.Logger.Printf("unsupported PEM type: %s\n",
			html.EscapeString(block.Type))
		i.params.FailureWriter(w, r, "unsupported PEM type",
			http.StatusBadRequest)
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		i.params.Logger.Println(err)
		i.params.FailureWriter(w, r, "invalid DER", http.StatusBadRequest)
		return nil
	}
	template, certDER, err := i.generateRoleCert(pub, callerArn)
	if err != nil {
		i.params.Logger.Println(err)
		i.params.FailureWriter(w, r, err.Error(),
			http.StatusInternalServerError)
		return nil
	}
	pem.Encode(w, &pem.Block{Bytes: certDER, Type: "CERTIFICATE"})
	return template
}

// Returns template and signed certificate DER.
func (i *Issuer) generateRoleCert(publicKey interface{},
	callerArn arn.ARN) (*x509.Certificate, []byte, error) {
	template, err := makeCertificateTemplate(callerArn)
	if err != nil {
		return nil, nil, err
	}
	certDER, err := i.params.CertificateGenerator(template, publicKey)
	if err != nil {
		return nil, nil, err
	}
	i.params.Logger.Printf(
		"Generated x509 Certificate for ARN=`%s`, expires=%s",
		callerArn.String(), template.NotAfter)
	return template, certDER, nil
}
