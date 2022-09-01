package aws_identity_cert

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

const (
	awsClaimedArnBad  = "arn:aws:iam::accountid:aResource/bogus"
	awsClaimedArnGood = "arn:aws:iam::accountid:role/TestMonkey"
)

type testCallerType struct {
	arn string
}

func (c *testCallerType) GetCallerIdentity(ctx context.Context,
	presignedMethod string, presignedUrl string) (arn.ARN, error) {
	parsedArn, _ := arn.Parse(c.arn)
	return parsedArn, nil
}

func TestGetCallerIdentity(t *testing.T) {
	header := make(http.Header)
	header.Add("claimed-arn", awsClaimedArnBad)
	header.Add("presigned-method", "GET")
	header.Add("presigned-url", "https://some.website/")
	parsedArn, err := getCallerIdentity(header,
		&testCallerType{awsClaimedArnGood})
	if err == nil {
		t.Errorf("no error with mismatched ARN")
	}
	header = make(http.Header)
	header.Add("claimed-arn", awsClaimedArnGood)
	header.Add("presigned-method", "GET")
	header.Add("presigned-url", "https://some.website/")
	parsedArn, err = getCallerIdentity(header,
		&testCallerType{awsClaimedArnGood})
	if err != nil {
		t.Fatal(err)
	}
	if parsedArn.String() != awsClaimedArnGood {
		t.Errorf("expected: %s but got: %s", awsClaimedArnGood, parsedArn)
	}
}

func TestMakeCertificateTemplate(t *testing.T) {
	callerArn, err := arn.Parse(awsClaimedArnBad)
	if err != nil {
		t.Fatal(err)
	}
	_, err = makeCertificateTemplate(callerArn)
	if err == nil {
		t.Errorf("no error with bad ARN: %s", awsClaimedArnBad)
	}
	callerArn, err = arn.Parse(awsClaimedArnGood)
	if err != nil {
		t.Fatal(err)
	}
	template, err := makeCertificateTemplate(callerArn)
	if err != nil {
		t.Error(err)
	}
	expected := roleCommonName(callerArn)
	if template.Subject.CommonName != expected {
		t.Errorf("expected common name: %s but got: %s",
			expected, template.Subject.CommonName)
	}
}

func TestRoleCommonName(t *testing.T) {
	callerArn, err := arn.Parse(awsClaimedArnGood)
	if err != nil {
		t.Fatal(err)
	}
	computed := roleCommonName(callerArn)
	expected := "aws:iam:accountid:TestMonkey"
	if computed != expected {
		t.Errorf("expected common name: %s but got: %s", expected, computed)
	}
}
