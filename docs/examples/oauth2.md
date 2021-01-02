# Oauth2

**Warning: For this flow, the part before the @ in the e-mail address is
considered the login. Be sure to limit who can oauth2 in by using internal
or private tokens. For example myuser@example.com is the same as
myuser@gmail.com if I choose Google as my oauth2 provider.**

If you have an external source of truth for users that also provides an oauth2
endpoint, you can allow your users to login and register their second factor.

## Keymaster config.yml

1. Enable oauth2 in the web flow via keymaster

```
-  allowed_auth_backends_for_webui: [ "TOTP", "U2F" ]
+  allowed_auth_backends_for_webui: [ "federated", "TOTP", "U2F" ]
```

1. a - **OPTIONAL** Enable TOTP registration

```
-  enable_local_totp: false
+  enable_local_totp: true
```

1. b - **OPTIONAL** Disable non oauth2 login for web flow

```
-  hide_standard_login: false
+  hide_standard_login: true
```

```
-  allowed_auth_backends_for_webui: [ "TOTP", "U2F" ]
+  allowed_auth_backends_for_webui: [ "federated" ]
```

2. Enable oauth2. This example uses Google, but you may need to visit
https://endpoint/.well-known/openid-configuration for the correct entries.

**NOTE**: During registration for your oauth2 token, you will be asked for an
allowed redirect URL. That should be:
**https://keymaster.example.com/auth/oauth2/callback**

[Example](https://accounts.google.com/.well-known/openid-configuration)

```
oauth2:
  config: null
  enabled: true
  client_id: "random-text.apps.googleusercontent.com"
  client_secret: "My-Secret-Id"
  token_url: "https://oauth2.googleapis.com/token"
  auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
  userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo"
  scopes: "openid profile email"
```
