package vip

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"text/template"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/util"
)

// The symantec VIP endpoint is very specific on namespaces, and golang's
// XML package is not very good with marshaling namespaces thus we will write
// requests using the text template. but parse them using the xml library
type vipValidateRequest struct {
	RequestId string `xml:"RequestId,attr"`
	TokenId   string `xml:"TokenId"`
	OTP       int    `xml:"OTP"`
}

type validateRequestBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipValidateRequest vipValidateRequest `xml:"Validate"`
	}
}

const validateRequestTemplate = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices">
   <soapenv:Header/>
   <soapenv:Body>
      <vip:AuthenticateCredentialsRequest>
         <vip:requestId>{{.RequestId}}</vip:requestId>
         <vip:credentials>
            <vip:credentialId>{{.TokenId}}</vip:credentialId>
            <vip:credentialType>STANDARD_OTP</vip:credentialType>
         </vip:credentials>
         <vip:otpAuthData>
         <vip:otp>{{printf "%06d" .OTP}}</vip:otp>
         </vip:otpAuthData>
      </vip:AuthenticateCredentialsRequest>
   </soapenv:Body>
</soapenv:Envelope>`

type authenticateCredentialsResponse struct {
	RequestId      string `xml:"requestId"`
	Status         string `xml:"status"`
	StatusMessage  string `xml:"statusMessage,omitempty"`
	CredentialId   string `xml:"credentialId,omitempty"`
	CredentialType string `xml:"credentialType,omitempty"`
	Detail         string `xml:"detail,omitempty"`
	DetailMessage  string `xml:"detailMessage,omitempty"`
}

type authenticateCredentialsResponseBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		AuthenticateCredentialsResponse authenticateCredentialsResponse `xml:"AuthenticateCredentialsResponse"`
	}
}

type vipUserInfoRequest struct {
	RequestId string `xml:"requestId"`
	UserId    string `xml:"userId"`
}

const userInfoRequestTemplate = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices">
   <soapenv:Header/>
   <soapenv:Body>
      <vip:GetUserInfoRequest>
         <vip:requestId>{{.RequestId}}</vip:requestId>
         <vip:userId>{{.UserId}}</vip:userId>
         <!--Optional:-->
         <vip:iaInfo>false</vip:iaInfo>
         <!--Optional:-->
         <vip:includePushAttributes>true</vip:includePushAttributes>
      </vip:GetUserInfoRequest>
   </soapenv:Body>
</soapenv:Envelope>`

type vipResponseBindingDetail struct {
	ReasonCode    string `xml:"bindStatus,omitempty"`
	FriendlyName  string `xml:"friendlyName,omitempty"`
	LastBindTime  string `xml:"lastBindTime,omitempty"`
	LastAuthnTime string `xml:"lastAuthnTime,omitempty"`
	LastAuthnId   string `xml:"lastAuthnId,omitempty"`
}
type vipResponseCredentialBindingDetail struct {
	CredentialId     string                   `xml:"credentialId,omitempty"`
	CredentialType   string                   `xml:"credentialType,omitempty"`
	CredentialStatus string                   `xml:"credentialStatus,omitempty"`
	BindingDetail    vipResponseBindingDetail `xml:"bindingDetail"`
}

type vipResponseGetUserInfo struct {
	RequestId               string                               `xml:"requestId"`
	Status                  string                               `xml:"status"`
	StatusMessage           string                               `xml:"statusMessage"`
	UserId                  string                               `xml:"userId"`
	UserCreationTime        string                               `xml:"userCreationTime"`
	UserStatus              string                               `xml:"userStatus"`
	NumBindings             string                               `xml:"numBindings"`
	CredentialBindingDetail []vipResponseCredentialBindingDetail `xml:"credentialBindingDetail"`
}

type userInfoResponseBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipResponseGetUserInfo vipResponseGetUserInfo `xml:"GetUserInfoResponse"`
	}
}

type authenticateUserWithPushRequest struct {
	RequestId             string `xml:"requestId"`
	UserId                string `xml:"userId"`
	PushMessageText       string
	DisplayMessageText    string
	DisplayMessageProfile string
	RequireAppApproval    bool
}

const authenticateUserWithPushRequestTemplate = `<?xml version="1.0"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns="https://schemas.symantec.com/vip/2011/04/vipuserservices">
<S:Header/>
  <S:Body>
    <AuthenticateUserWithPushRequest>
      <requestId>{{.RequestId}}</requestId>
      <userId>{{.UserId}}</userId>
      <pushAuthData>
        <displayParameters>
          <Key>push.message.text</Key>
	   <Value>{{.PushMessageText}}</Value>
        </displayParameters>
        <displayParameters>
          <Key>display.message.title</Key>
          <Value>Sign In request</Value>
        </displayParameters>
        <displayParameters>
          <Key>display.message.text</Key>
          <Value>{{.DisplayMessageText}}</Value>
        </displayParameters>
        <displayParameters>
          <Key>display.message.profile</Key>
	  <Value>{{.DisplayMessageProfile}}</Value>
        </displayParameters>
        <requestParameters>
          <Key>request.timeout</Key>
          <Value>120</Value>
        </requestParameters>
        <requestParameters>
          <Key>nonactionable.notification</Key>
	  <Value>{{if .RequireAppApproval}}true{{else}}false{{end}}</Value>
        </requestParameters>
        <requestParameters>
          <Key>enforceLocalAuth</Key>
          <Value>false</Value>
        </requestParameters>
        <requestParameters>
          <Key>includeDeviceInfo</Key>
          <Value>true</Value>
        </requestParameters>
      </pushAuthData>
    </AuthenticateUserWithPushRequest>
  </S:Body>
</S:Envelope>`

/*
<?xml version="1.0"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Body>
    <AuthenticateUserWithPushResponse xmlns="https://schemas.symantec.com/vip/2011/04/vipuserservices">
      <requestId>AUTHWPUSH_47348263001</requestId>
      <status>6040</status>
      <statusMessage>Mobile push request sent</statusMessage>
      <transactionId>b20e567dbf7bf7e9</transactionId>
      <pushDetail>
        <pushCredentialId>SYMC61713435</pushCredentialId>
        <pushSent>true</pushSent>
      </pushDetail>
    </AuthenticateUserWithPushResponse>
  </S:Body>
</S:Envelope>
*/

type vipResponsePushDetail struct {
	PushCredentialId string `xml:"pushCredentialId,omitempty"`
	PushSent         string `xml:"pushSent,omitempty"`
}

type vipResponseAuthenticateUserWithPush struct {
	RequestId     string                  `xml:"requestId"`
	Status        string                  `xml:"status"`
	StatusMessage string                  `xml:"statusMessage"`
	TransactionId string                  `xml:"transactionId"`
	PushDetail    []vipResponsePushDetail `xml:"pushDetail"`
}

type authenticateUserWithPushResponseBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipResponseAuthenticateUserWithPush vipResponseAuthenticateUserWithPush `xml:"AuthenticateUserWithPushResponse"`
	}
}

type pollStatusRequest struct {
	RequestId     string `xml:"requestId"`
	TransactionId string `xml:"transactionId"`
}

const pollStatusRequestTemplate = `<?xml version="1.0"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns="https://schemas.symantec.com/vip/2011/04/vipuserservices">
  <S:Header/>
  <S:Body>
          <PollPushStatusRequest>
                  <requestId>{{.RequestId}}</requestId>
      <transactionId>{{.TransactionId}}</transactionId>
    </PollPushStatusRequest>
  </S:Body>
</S:Envelope>`

/*
fail poll response
<?xml version="1.0" encoding="UTF-8"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Body>
    <PollPushStatusResponse xmlns="https://schemas.symantec.com/vip/2011/04/vipuserservices">
      <requestId>AUTHWPUSH_47348263001</requestId>
      <status>0000</status>
      <statusMessage>Success</statusMessage>
      <transactionStatus>
        <transactionId>c312be521d2a4b7e</transactionId>
        <status>7005</status>
        <statusMessage>Mobile push request not found</statusMessage>
      </transactionStatus>
    </PollPushStatusResponse>
  </S:Body>
</S:Envelope>
*/

type PollResponseDeviceInfo struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type vipResponsePollPushTransactionStatus struct {
	TransactionId  string                   `xml:"transactionId"`
	Status         string                   `xml:"status"`
	StatusMessage  string                   `xml:"statusMessage"`
	AuthnTime      string                   `xml:"authnTime,omitempty"`
	CredentialId   string                   `xml:"credentialId,omitempty"`
	CredentialType string                   `xml:"credentialType,omitempty"`
	DeviceInfo     []PollResponseDeviceInfo `xml:"deviceInfo,omitempty"`
}

type vipResponsePollPushStatus struct {
	RequestId         string                                 `xml:"requestId"`
	Status            string                                 `xml:"status"`
	StatusMessage     string                                 `xml:"statusMessage"`
	TransactionId     string                                 `xml:"transactionId"`
	TransactionStatus []vipResponsePollPushTransactionStatus `xml:"transactionStatus"`
}

type pollPushResponseBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipResponsePollPushStatus vipResponsePollPushStatus `xml:"PollPushStatusResponse"`
	}
}

/*
successful poll responst
<?xml version="1.0"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Body>
    <PollPushStatusResponse xmlns="https://schemas.symantec.com/vip/2011/04/vipuserservices">
      <requestId>AUTHWPUSH_47348263001</requestId>
      <status>0000</status>
      <statusMessage>Success</statusMessage>
      <transactionStatus>
        <transactionId>c312be521d2a4b7e</transactionId>
        <status>7000</status>
        <statusMessage>Mobile push request approved by user</statusMessage>
        <authnTime>1970-01-01T00:00:00.000Z</authnTime>
        <credentialId>SYMC61713435</credentialId>
        <credentialType>STANDARD_OTP</credentialType>
        <deviceInfo>
          <Key>os</Key>
          <Value>iOS</Value>
        </deviceInfo>
        <deviceInfo>
          <Key>osVersion</Key>
          <Value>11.2.5</Value>
        </deviceInfo>
        <deviceInfo>
          <Key>vipAccessVersion</Key>
          <Value>4.2.3</Value>
        </deviceInfo>
      </transactionStatus>
    </PollPushStatusResponse>
  </S:Body>
</S:Envelope>
*/

type Client struct {
	Cert                            tls.Certificate
	VipUserServicesURL              string
	VipUserServiceAuthenticationURL string
	RootCAs                         *x509.CertPool
	VipPushMessageText              string //what is shown on the shown on the alarm
	VipPushDisplayMessageText       string // what is shown after
	VipPushDisplayMessageProfile    string // The url?
	Debug                           bool
	RequireAppApproval              bool
}

func NewClient(certPEMBlock, keyPEMBlock []byte) (client Client, err error) {

	client.Cert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return client, err
	}
	//This is the production url for vipservices
	client.VipUserServicesURL = "https://userservices-auth.vip.symantec.com/vipuserservices/QueryService_1_8"
	//https://userservices-auth.vip.symantec.com/vipuserservices/QueryService_1_8
	client.VipUserServiceAuthenticationURL = "https://userservices-auth.vip.symantec.com/vipuserservices/AuthenticationService_1_8"

	client.VipPushMessageText = "Symantec Push Authentication Request"
	client.VipPushDisplayMessageText = "Sign In request from Some site"
	client.VipPushDisplayMessageProfile = "www.example.com"

	return client, nil
}

func (client *Client) postBytesVip(data []byte, targetURL string, contentType string) ([]byte, error) {
	//two steps... convert data into post data!
	req, err := util.CreateSimpleDataBodyRequest("POST", targetURL, data, contentType)
	if err != nil {
		return nil, err
	}
	// make client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{client.Cert},
		RootCAs:      client.RootCAs,
		MinVersion:   tls.VersionTLS12}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	postResponse, err := httpClient.Do(req)
	if err != nil {
		log.Printf("got error from req")
		log.Println(err)
		// TODO: differentiate between 400 and 500 errors
		// is OK to fail.. try next
		return nil, err
	}
	defer postResponse.Body.Close()
	if postResponse.StatusCode != 200 {
		log.Printf("got error from login call %s", postResponse.Status)
		return nil, err
	}
	return ioutil.ReadAll(postResponse.Body)
}

func (client *Client) postBytesUserServices(data []byte) ([]byte, error) {
	return client.postBytesVip(data, client.VipUserServicesURL, "text/xml")
}

func (client *Client) postBytesUserServicesAuthentication(data []byte) ([]byte, error) {
	return client.postBytesVip(data, client.VipUserServiceAuthenticationURL, "text/xml")
}

func genNewRequestID() string {
	nBig, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		panic(err)
	}
	return nBig.String()
}

func (client *Client) VerifySingleToken(tokenID string, tokenValue int) (bool, error) {
	requestID := genNewRequestID()
	validateRequest := vipValidateRequest{RequestId: requestID,
		TokenId: tokenID, OTP: tokenValue}
	tmpl, err := template.New("validate").Parse(validateRequestTemplate)
	if err != nil {
		panic(err)
	}
	var requestBuffer bytes.Buffer

	//err = tmpl.Execute(os.Stdout, validateRequest)
	err = tmpl.Execute(&requestBuffer, validateRequest)
	if err != nil {
		panic(err)
	}
	responseBytes, err := client.postBytesUserServicesAuthentication(requestBuffer.Bytes())
	if err != nil {
		return false, err
	}
	var response authenticateCredentialsResponseBody
	err = xml.Unmarshal(responseBytes, &response)
	if err != nil {
		fmt.Print(err)
	}
	//fmt.Printf("%+v", response)
	switch response.Body.AuthenticateCredentialsResponse.Status {
	case "0000":
		return true, nil
	default:
		return false, nil
	}
	panic("should never have reached this point")
}

func (client *Client) GetActiveTokens(userID string) ([]string, error) {
	requestID := genNewRequestID()
	userInfoRequest := vipUserInfoRequest{RequestId: requestID,
		UserId: userID}

	tmpl, err := template.New("userInfo").Parse(userInfoRequestTemplate)
	if err != nil {
		panic(err)
	}
	var requestBuffer bytes.Buffer

	err = tmpl.Execute(&requestBuffer, userInfoRequest)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("\nbuffer='%s'\n", requestBuffer.String())
	responseBytes, err := client.postBytesUserServices(requestBuffer.Bytes())
	if err != nil {
		return nil, err
	}

	var response userInfoResponseBody
	err = xml.Unmarshal(responseBytes, &response)
	if err != nil {
		fmt.Print(err)
	}
	// TODO verify response requestID matches ours
	//fmt.Printf("%+v", response)
	/*
		output, err := xml.MarshalIndent(&response, " ", "    ")
		if err != nil {
			fmt.Printf("error: %v\n", err)
		}
		fmt.Println(output)
	*/
	var enabledTokenID []string
	for _, credentialBinding := range response.Body.VipResponseGetUserInfo.CredentialBindingDetail {
		if client.Debug {
			log.Printf("\n%+v\n", credentialBinding)
		}
		if credentialBinding.CredentialStatus != "ENABLED" {
			continue
		}
		enabledTokenID = append(enabledTokenID, credentialBinding.CredentialId)
	}

	return enabledTokenID, nil
}

func (client *Client) ValidateUserOTP(userID string, OTPValue int) (bool, error) {
	tokenList, err := client.GetActiveTokens(userID)
	if err != nil {
		return false, err
	}
	if len(tokenList) < 1 {
		return false, nil
	}
	// TODO: replace this loop for a single call in the API
	for _, tokenId := range tokenList {
		ok, err := client.VerifySingleToken(tokenId, OTPValue)
		if err != nil {
			continue
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (client *Client) StartUserVIPPush(userID string) (transactionID string, err error) {
	requestID := genNewRequestID()
	vipPushRequest := authenticateUserWithPushRequest{
		RequestId:             requestID,
		UserId:                userID,
		PushMessageText:       client.VipPushMessageText,
		DisplayMessageText:    client.VipPushDisplayMessageText,
		DisplayMessageProfile: client.VipPushDisplayMessageProfile,
		RequireAppApproval:    client.RequireAppApproval,
	}
	tmpl, err := template.New("pushRequest").Parse(authenticateUserWithPushRequestTemplate)
	if err != nil {
		panic(err)
	}
	var requestBuffer bytes.Buffer

	err = tmpl.Execute(&requestBuffer, vipPushRequest)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("\nbuffer='%s'\n", requestBuffer.String())
	responseBytes, err := client.postBytesUserServicesAuthentication(requestBuffer.Bytes())
	if err != nil {
		return "", err
	}

	var response authenticateUserWithPushResponseBody
	err = xml.Unmarshal(responseBytes, &response)
	if err != nil {
		fmt.Print(err)
	}
	if client.Debug {
		log.Printf("%+v", response)
	}
	if response.Body.VipResponseAuthenticateUserWithPush.Status != "6040" {
		err := errors.New("bad push status")
		return "", err
	}
	return response.Body.VipResponseAuthenticateUserWithPush.TransactionId, nil
}

func (client *Client) VipPushHasBeenApproved(transactionID string) (bool, error) {
	requestID := genNewRequestID()
	vipPollRequest := pollStatusRequest{RequestId: requestID,
		TransactionId: transactionID}
	tmpl, err := template.New("pushRequest").Parse(pollStatusRequestTemplate)
	if err != nil {
		panic(err)
	}
	var requestBuffer bytes.Buffer
	err = tmpl.Execute(&requestBuffer, vipPollRequest)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("\nbuffer='%s'\n", requestBuffer.String())
	responseBytes, err := client.postBytesUserServices(requestBuffer.Bytes())
	if err != nil {
		return false, err
	}

	var response pollPushResponseBody
	err = xml.Unmarshal(responseBytes, &response)
	if err != nil {
		fmt.Print(err)
	}
	if client.Debug {
		log.Printf("%+v", response)
	}
	if response.Body.VipResponsePollPushStatus.Status != "0000" {
		// TODO: this should be non nil
		err := errors.New("bad poll request status")
		return false, err
	}
	if len(response.Body.VipResponsePollPushStatus.TransactionStatus) < 1 {
		err := errors.New("invalid response")
		return false, err
	}
	transactionStatus := response.Body.VipResponsePollPushStatus.TransactionStatus[0]
	if client.Debug {
		log.Printf("%+v", transactionStatus)
	}
	// TODO: replace this for a switch statement
	if transactionStatus.Status != "7000" {
		return false, nil
	}

	return true, nil
}
