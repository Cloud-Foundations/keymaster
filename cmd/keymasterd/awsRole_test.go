package main

import (
	"fmt"
	"net"
	"net/http"
	"testing"
)

const (
	awsClaimedArnBad          = "arn:aws:iam::accountid:role/IntruderAlert"
	awsClaimedArnGood         = "arn:aws:iam::accountid:role/TestMonkey"
	awsPresignedUrlBadAction  = "https://sts.a-region.amazonaws.com/?Action=BecomeRoot&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=cred&X-Amz-Security-Token=token&X-Amz-SignedHeaders=host&X-Amz-Signature=sig"
	awsPresignedUrlBadDomain  = "https://sts.a-region.hackerz.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=cred&X-Amz-Security-Token=token&X-Amz-SignedHeaders=host&X-Amz-Signature=sig"
	awsPresignedUrlGood       = "https://sts.a-region.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=cred&X-Amz-Security-Token=token&X-Amz-SignedHeaders=host&X-Amz-Signature=sig"
	awsCallerIdentityResponse = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::accountid:assumed-role/TestMonkey/tester</Arn>
    <UserId>useridstuff:tester</UserId>
    <Account>accountid</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>some-uuid</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
`
)

type testAwsGetCallerIdentityType struct{}

func testValidatePresignedUrl(presignedUrl string) error { return nil }

func (testAwsGetCallerIdentityType) ServeHTTP(w http.ResponseWriter,
	r *http.Request) {
	w.Write([]byte(awsCallerIdentityResponse))
}

func TestAwsPresignedUrlValidation(t *testing.T) {
	if err := validateStsPresignedUrl(awsPresignedUrlBadAction); err == nil {
		t.Error(err)
	}
	if err := validateStsPresignedUrl(awsPresignedUrlBadDomain); err == nil {
		t.Error(err)
	}
	if err := validateStsPresignedUrl(awsPresignedUrlGood); err != nil {
		t.Error("valid URL does not validate")
	}
}

func TestAwsGetCallerIdentity(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err := http.Serve(listener, &testAwsGetCallerIdentityType{})
		if err != nil {
			t.Fatal(err)
		}
	}()
	header := make(http.Header)
	header.Add("claimed-arn", awsClaimedArnBad)
	header.Add("presigned-method", "GET")
	header.Add("presigned-url",
		fmt.Sprintf("http://%s/", listener.Addr().String()))
	parsedArn, err := getCallerIdentity(header, testValidatePresignedUrl)
	if err == nil {
		t.Error(err)
	}
	header = make(http.Header)
	header.Add("claimed-arn", awsClaimedArnGood)
	header.Add("presigned-method", "GET")
	header.Add("presigned-url",
		fmt.Sprintf("http://%s/", listener.Addr().String()))
	parsedArn, err = getCallerIdentity(header, testValidatePresignedUrl)
	if err != nil {
		t.Fatal(err)
	}
	if parsedArn.parsedArn.String() !=
		"arn:aws:iam::accountid:role/TestMonkey" {
		t.Errorf("expected: arn:aws:iam::accountid:role/TestMonkey but got: %s",
			parsedArn.parsedArn)
	}
	if parsedArn.role != "TestMonkey" {
		t.Errorf("expected role: TestMonkey != %s", parsedArn.role)
	}
}
