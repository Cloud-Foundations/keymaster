package main

import (
	"html/template"
	"time"
)

const headerTemplateText = `
{{define "header"}}
{{if .SessionExpires}}
<section
 id="session-data"
 date="{{.SessionExpires}}"
></section>
{{end}}
<div class="header">
<table style="width:100%;border-collapse: separate;border-spacing: 0;">
  <tr>
    <th style="text-align:left;"> <div class="header_extra">
      {{template "header_extra"}}</div>
    </th>
    <th style="text-align:right;padding-right: .5em;">
      {{if .AuthUsername}}
      <b id="authUsername">{{.AuthUsername}}</b>
      &nbsp;&nbsp;<a href="/api/v0/logout">Logout</a>
      {{end}}
    </th>
  </tr>
</table>
</div>

{{end}}
`

const footerTemplateText = `
{{define "footer"}}

<div class="footer">
<hr>
<center>
Copyright 2017-2019 Symantec Corporation; 2019-2025 Cloud-Foundations.org.
{{template "footer_extra"}}
</center>
</div>
{{end}}
`

type loginPageTemplateData struct {
	Title                 string
	AuthUsername          string
	SessionExpires        int64
	DefaultUsername       string
	JSSources             []string
	ShowBasicAuth         bool
	ShowOauth2            bool
	LoginDestinationInput template.HTML
	ErrorMessage          string
}

const loginFormText = `
{{define "loginPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
	<link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
	<link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
        <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
    </head>
    <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
        <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">
        <h2> Keymaster Login </h2>
	{{if .ErrorMessage}}
	<p style="color:red;">{{.ErrorMessage}} </p>
	{{end}}
	{{if .ShowOauth2}}
	<p>
    <form enctype="application/x-www-form-urlencoded" action="/auth/oauth2/login" method="post">
    {{if .LoginDestinationInput}}
	 {{.LoginDestinationInput}}
    {{end}}
    <p><input type="submit" value="Oauth2 Login" /></p>
    </form>
	</p>
    {{end}}
    {{if .ShowBasicAuth}}
	{{template "login_pre_password" .}}
        <form enctype="application/x-www-form-urlencoded" action="/api/v0/login" method="post">
            {{if .DefaultUsername}}
            <p>Username: <INPUT TYPE="text" NAME="username" VALUE={{.DefaultUsername}} SIZE=18></p>
            <p>Password: <INPUT TYPE="password" NAME="password" SIZE=18  autocomplete="off" autofocus></p>
            {{else}}
            <p>Username: <INPUT TYPE="text" NAME="username" SIZE=18 autofocus></p>
            <p>Password: <INPUT TYPE="password" NAME="password" SIZE=18  autocomplete="off"></p>
            {{end}}
	    {{.LoginDestinationInput}}
            <p><input type="submit" value="Submit" /></p>
        </form>
    {{end}}
	{{template "login_form_footer" .}}
	</div>
    {{template "footer" . }}
    </div>
    </body>
</html>
{{end}}
`

type secondFactorAuthTemplateData struct {
	Title                 string
	AuthUsername          string
	SessionExpires        int64
	JSSources             []string
	ShowBootstrapOTP      bool
	ShowVIP               bool
	ShowU2F               bool
	ShowTOTP              bool
	ShowOktaOTP           bool
	LoginDestinationInput template.HTML
}

const secondFactorAuthFormText = `
{{define "secondFactorLoginPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
        {{if .JSSources -}}
        {{- range .JSSources }}
        <script type="text/javascript" src="{{.}}"></script>
        {{- end}}
        {{- end}}
        <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
        <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
        <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
    </head>
    <body>
        <div  style="min-height:100%;position:relative;">
	{{template "header" .}}
	<div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">
        <h2> Keymaster second factor authentication </h2>
	{{if .ShowBootstrapOTP}}
        <form enctype="application/x-www-form-urlencoded" action="/api/v0/bootstrapOtpAuth" method="post">
            <p>
	    Enter Bootstrap OTP value: <INPUT TYPE="text" NAME="OTP" SIZE=18  autocomplete="off">
	    {{.LoginDestinationInput}}
            <input type="submit" value="Submit" />
	    </p>
        </form>
	{{end}}
	{{if .ShowVIP}}
        <form enctype="application/x-www-form-urlencoded" action="/api/v0/vipAuth" method="post">
            <p>
	    Enter VIP token value: <INPUT TYPE="text" NAME="OTP" SIZE=18  autocomplete="off">
	    {{.LoginDestinationInput}}
            <input type="submit" value="Submit" />
	    </p>
        </form>
	{{if .ShowU2F}}
	<div id="otp_or_u2f_message">
	<p>
	<h4>Or</h4>
	</p>
	</div>
	{{else}}
	<p> Or wait for a VIP push</p>
	{{end}}
	{{end}}

	{{if .ShowU2F}}
	<p>
               <div id="auth_action_text" > Authenticate by touching a blinking registered U2F device (insert if not inserted yet)</div>
        </p>
        {{if .ShowVIP}}
	<div id="manual_start_vip_div">
	<p>
	<h4>Or</h4>
	</p>
	<p> <button id="start_vip_push_button" >Start VIP Push</button>(VIP push will autostart in a few seconds)</p>
        </div>
	{{end}}
	{{end}}

        {{if .ShowTOTP}}
        <form enctype="application/x-www-form-urlencoded" action="/api/v0/TOTPAuth" method="post">
            <p>
            Enter TOTP token value: <INPUT TYPE="text" NAME="OTP" SIZE=18  autocomplete="off">
	     {{.LoginDestinationInput}}
            <input type="submit" value="Submit" />
            </p>
        </form>
	{{end}}

        {{if .ShowOktaOTP}}
        <form enctype="application/x-www-form-urlencoded" action="/api/v0/okta2FAAuth" method="post">
            <p>
            Okta push has been automatically started. If you are not able to receive the
            push notification you can proceed by entering the Okta OTP code.
            </p>
            <p>
            Enter TOTP token value: <INPUT TYPE="text" NAME="OTP" SIZE=18  autocomplete="off">
	    {{.LoginDestinationInput}}
            <input type="submit" value="Submit" />
            </p>
        </form>
	{{end}}
	<form enctype="application/x-www-form-urlencoded" action="/api/v0/logout" method="post">
            <br>
	    <p>
	    If you have login issues, you can also
	    <input type="submit" value="Logout" />
	     {{.LoginDestinationInput}}
	    </p>
	</form>
	</div>
	{{template "footer" . }}
	</div>
	</body>
</html>
{{end}}
`

type usersPageTemplateData struct {
	Title          string
	AuthUsername   string
	SessionExpires int64
	JSSources      []string
	Users          []string
}

const usersHTML = `
{{define "usersPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
  <head>
    <title>{{.Title}}</title>
    {{if .JSSources -}}
    {{- range .JSSources }}
    <script type="text/javascript" src="{{.}}"></script>
    {{- end}}
    {{- end}}
    <!-- The original u2f-api.js code can be found here:
    https://github.com/google/u2f-ref-code/blob/master/u2f-gae-demo/war/js/u2f-api.js -->
    <!-- script type="text/javascript" src="https://demo.yubico.com/js/u2f-api.js"></script-->
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
    <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
    <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
  </head>
  <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
    <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">

    <h1>{{.Title}}</h1>
    <ul>
    {{range .Users}}
       <li><a href="/profile/{{.}}">{{.}}</a></li>
    {{end}}
    </ul>
    <br>
    <h3>Manage Users </h3>
    <form enctype="application/x-www-form-urlencoded" action="/admin/addUser" method="post">
       <p>Username: <INPUT TYPE="text" NAME="username" SIZE=18  autocomplete="off"></p>
       <p><input type="submit" value="Add User" /> </p>
       <p><input type="submit" value="Delete User" formaction="/admin/deleteUser" /> </p>
       <p><input type="submit" value="Generate BootstrapOTP" formaction="/admin/newBoostrapOTP" /> </p>
    </form>

    </div>
    {{template "footer" . }}
    </div>
  </body>
</html>
{{end}}
`

type registeredU2FTokenDisplayInfo struct {
	RegistrationDate time.Time
	DeviceData       string
	Name             string
	Index            int64
	Enabled          bool
}

type registeredTOTPTDeviceDisplayInfo struct {
	RegistrationDate time.Time
	Name             string
	Index            int64
	Enabled          bool
}

type bootstrapOtpTemplateData struct {
	ExpiresAt   time.Time
	Fingerprint [4]byte
}

type profilePageTemplateData struct {
	Title                string
	AuthUsername         string
	Username             string
	SessionExpires       int64
	JSSources            []string
	BootstrapOTP         *bootstrapOtpTemplateData
	ShowU2F              bool
	ShowTOTP             bool
	ReadOnlyMsg          string
	UsersLink            bool
	ShowLegacyRegister   bool
	RegisteredU2FToken   []registeredU2FTokenDisplayInfo
	RegisteredTOTPDevice []registeredTOTPTDeviceDisplayInfo
}

const profileHTML = `
{{define "userProfilePage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
  <head>
    <title>{{.Title}}</title>
    {{if .JSSources -}}
    {{- range .JSSources }}
    <script type="text/javascript" src="{{.}}"></script>
    {{- end}}
    {{- end}}
    <!-- The original u2f-api.js code can be found here:
    https://github.com/google/u2f-ref-code/blob/master/u2f-gae-demo/war/js/u2f-api.js -->
    <!-- script type="text/javascript" src="https://demo.yubico.com/js/u2f-api.js"></script-->
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
    <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
    <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
  </head>
  <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
    <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">

    {{with $top := . }}
    <h1>Keymaster User Profile</h1>
    <h2 id="username">{{.Username}}</h2>
    {{.ReadOnlyMsg}}
    <ul>
      <li><a href="/api/v0/logout" >Logout </a></li>
    {{if .UsersLink}}
      <li><a href="/users/">Users</a></li>
    {{end}}
    </ul>
    {{if .BootstrapOTP}}
    <div id="bootstrap-otp">
    Bootstrap OTP fingerprint: <code>{{printf "%x" .BootstrapOTP.Fingerprint}}</code>
    expires at: {{.BootstrapOTP.ExpiresAt}}<p>
    </div>
    {{end}}
    <div id="u2f-tokens">
    <h3>U2F</h3>
    <ul>
       {{if .ShowU2F}}
       {{if not .ReadOnlyMsg}}
       {{if .ShowLegacyRegister}}
      <li>
         <a id="register_button" href="#">Register token (Legacy)</a>
         <div id="register_action_text" style="color: blue;background-color: yellow; display: none;"> Please Touch the blinking device to register(insert if not inserted yet) </div>
      </li>
      {{end}}
      {{end}}
      <li><a id="webauthn_auth_button" href="#">Authenticate</a>
      </li>
      <li><a id="webauthn_register_button" href="#">Register U2F device</a>
      </li>
      {{else}}
      <div id="auth_action_text" style="color: blue;background-color: yellow;"> Your browser does not support U2F. However you can still Enable/Disable/Delete U2F tokens </div>
      {{end}}
    </ul>
    <div style="margin-left: 40px">
    {{if .RegisteredU2FToken -}}
        <p>Your U2F Token(s):</p>
        <table>
	    <tr>
	    <th>Name</th>
	    <th>Device Data</th>
	    <th>Actions</th>
	    </tr>
	    {{- range .RegisteredU2FToken }}
            <tr>
	     <form enctype="application/x-www-form-urlencoded" action="/api/v0/manageU2FToken" method="post">
	     <input type="hidden" name="index" value="{{.Index}}">
	     <input type="hidden" name="username" value="{{$top.Username}}">
	     <td> <input type="text" name="name" value="{{ .Name}}" SIZE=18  {{if $top.ReadOnlyMsg}} readonly{{end}} > </td>
	     <td> {{ .DeviceData}} </td>
	     <td>
	         {{if not $top.ReadOnlyMsg}}
	         <input type="submit" name="action" value="Update" {{if not .Enabled}} disabled {{end}}/>
		 {{if .Enabled}}
		 <input type="submit" name="action" value="Disable"/>
		 {{ else }}
		 <input type="submit" name="action" value="Enable"/>
		 <input type="submit" name="action" value="Delete" {{if .Enabled}} disabled {{end}}/>
		 {{ end }}
		 {{end}}
	     </td>
	     </form>
	     </tr>
	    {{- end}}
	</table>
    {{- else}}
	You Dont have any registered tokens.
    {{- end}}
    </div>
    </div> <!-- end of u2f div -->
    <div id="totp-tokens">
    {{if .ShowTOTP}}
       <h3>TOTP</h3>
       <ul>
          <li><a href="/totp/GenerateNew/">Generate New TOTP</a></li>
	  <li>
              <form enctype="application/x-www-form-urlencoded" action="/api/v0/VerifyTOTP" method="post">
                  <p>
                  Authenticate TOTP: <INPUT TYPE="text" NAME="OTP" SIZE=8  autocomplete="off">
                  <INPUT TYPE="hidden" NAME="login_destination" VALUE="/">
                  <input type="submit" value="Submit" />
                  </p>
              </form>
	  </li>
       </ul>
       {{if .RegisteredTOTPDevice -}}
       <div style="margin-left: 40px">
       <p> Your registered totp device(s) </p>
       <table>
            <tr>
               <th>Name</th>
               <th>Actions</th>
            </tr>
	    {{- range .RegisteredTOTPDevice }}
	    <tr>
	       <form enctype="application/x-www-form-urlencoded" action="/api/v0/manageTOTPToken" method="post">
                  <input type="hidden" name="index" value="{{.Index}}">
                  <input type="hidden" name="username" value="{{$top.Username}}">
                  <td> <input type="text" name="name" value="{{ .Name}}" SIZE=18  {{if $top.ReadOnlyMsg}} readonly{{end}} > </td>
                  <td>
                  {{if not $top.ReadOnlyMsg}}
                     <input type="submit" name="action" value="Update" {{if not .Enabled}} disabled {{end}}/>
                  {{if .Enabled}}
                     <input type="submit" name="action" value="Disable"/>
                  {{ else }}
                     <input type="submit" name="action" value="Enable"/>
                     <input type="submit" name="action" value="Delete" {{if .Enabled}} disabled {{end}}/>
                  {{ end }}
                  {{end}}
                  </td>
               </form>
	    </tr>
	    {{- end}}
       </table>
       </div><!-- end of RegisteredTOTPDevice div-->
       {{end}}
    {{end}}
    </div> <!-- end of totp div -->
    {{end}}
    </div>
    {{template "footer" . }}
    </div>
  </body>
</html>
{{end}}
`

type newTOTPPageTemplateData struct {
	Title           string
	AuthUsername    string
	SessionExpires  int64
	JSSources       []string
	ErrorMessage    string
	TOTPBase64Image template.HTML
	TOTPSecret      string
}

const newTOTPHTML = `
{{define "newTOTPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
  <head>
    <title>{{.Title}}</title>
    {{if .JSSources -}}
    {{- range .JSSources }}
    <script type="text/javascript" src="{{.}}"></script>
    {{- end}}
    {{- end}}
    <!-- The original u2f-api.js code can be found here:
    https://github.com/google/u2f-ref-code/blob/master/u2f-gae-demo/war/js/u2f-api.js -->
    <!-- script type="text/javascript" src="https://demo.yubico.com/js/u2f-api.js"></script-->
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
    <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
    <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
  </head>
  <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
    <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">

    <h1>{{.Title}}</h1>

    {{if .ErrorMessage}}
    <p style="color:red;">{{.ErrorMessage}} </p>
    {{end}}

    <div>

    {{if .TOTPBase64Image}}
    New TOTP:
    {{.TOTPBase64Image}}
    {{ end }}
    </div>
    <form enctype="application/x-www-form-urlencoded" action="/totp/ValidateNew/" method="post">
            <p>
            Enter OTP token value: <INPUT TYPE="text" NAME="OTP" SIZE=18  autocomplete="off">
            <input type="submit" value="Validate" />
            </p>
    </form>
    </div>
    {{template "footer" . }}
    </div>
  </body>
</html>
{{end}}
`

type newBootstrapOTPPPageTemplateData struct {
	Title             string
	AuthUsername      string
	SessionExpires    int64
	JSSources         []string
	ErrorMessage      string
	Username          string
	BootstrapOTPValue string
	ExpiresAt         time.Time
	Fingerprint       string
}

const newBootstrapOTPPHTML = `
{{define "newBoostrapOTPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
  <head>
    <title>{{.Title}}</title>
    {{if .JSSources -}}
    {{- range .JSSources }}
    <script type="text/javascript" src="{{.}}"></script>
    {{- end}}
    {{- end}}
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
    <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
    <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
  </head>
  <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
    <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">

    <h1>{{.Title}}</h1>

    {{if .ErrorMessage}}
    <p style="color:red;">{{.ErrorMessage}} </p>
    {{end}}

    <div>
    <p>
    New Bootstrap OTP for {{.Username}} registered, expires at {{.ExpiresAt}}<br>
    {{if .BootstrapOTPValue}}
    Bootstrap OTP value is "<code>{{.BootstrapOTPValue}}</code>"<br>
    {{end}}
    Bootstrap OTP fingerprint: <code>{{.Fingerprint}}</code>
    </p>
    </div>

    </div>
    {{template "footer" . }}
    </div>
  </body>
</html>
{{end}}
`

type authCodePageTemplateData struct {
	Title          string
	AuthUsername   string
	SessionExpires int64
	JSSources      []string
	ErrorMessage   string
	Token          string
}

const showAuthTokenHTML = `
{{define "authTokenPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
  <head>
    <title>{{.Title}}</title>
    {{if .JSSources -}}
    {{- range .JSSources }}
    <script type="text/javascript" src="{{.}}"></script>
    {{- end}}
    {{- end}}
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
    <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
    <link rel="stylesheet" type="text/css" href="/static/keymaster.css">
  </head>
  <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
    <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">

    <h1>{{.Title}}</h1>

    {{if .ErrorMessage}}
    <p style="color:red;">{{.ErrorMessage}} </p>
    {{end}}

    <div>
    <p>
    {{if .Token}}
    Copy into CLI:<p>
    <code><b>{{.Token}}</b></code>
    <p>
    Close this tab once entered.
    {{end}}
    </p>
    </div>

    </div>
    {{template "footer" . }}
    </div>
  </body>
</html>
{{end}}
`
