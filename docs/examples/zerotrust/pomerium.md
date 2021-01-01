# Pomerium

## What is Pomerium

[Pomerium](https://pomerium.com/) is an identity-aware proxy that enables secure
access to internal applications. Pomerium provides a standardized interface to
add access control to applications regardless of whether the application itself
has authorization or authentication baked-in. Pomerium gateways both internal
and external requests, and can be used in situations where you'd typically reach
for a VPN.

## Keymaster Config

```
openid_connect_idp:
  default_email_domain: "example.com"
  clients:
    - client_id: "pomerium"
      client_secret: "Pre-Shared-Key"
      allowed_redirect_domains:
        - "pomerium.example.com"
```

## Pomerium Config

Configure certificates and DNS as you would normally. You can get your own
certificates, use certbot to obtain wildcards or enable autocert. Once you have
that figured out, set up below is a good example.

```
authenticate_service_url: https://pomerium.example.com
signout_redirect_url: https://keymaster.example.com/api/v0/logout

idp_provider: oidc
idp_provider_url: https://keymaster.example.com
idp_client_id: pomerium
idp_client_secret: Pre-Shared-Key

cookie_expire: 16h
cookie_domain: pomerium.example.com
cookie_secret: (EXECUTE head -c32 /dev/urandom | base64)

policy:
  - from: https://site1.pomerium.example.com
    to: https://site1.internal.example.com:4422
    allow_websockets: false
    preserve_host_header: true
    tls_skip_verify: false
    allowed_idp_claims:
      groups:
        - marketing
        - product

  - from: https://site2.pomerium.example.com
    to: https://site2.internal.example.com:443
    allow_websockets: true
    preserve_host_header: false
    tls_skip_verify: true
    allowed_users:
      - user1@example.com
      - user2@example.com

  - from: https://site3.pomerium.example.com
    to: https://site3.internal.example.com:4422
    allow_websockets: true
    preserve_host_header: true
    tls_skip_verify: false
    allowed_domains:
      - example.com
```

## Congrats
You can now access internal websites without a VPN. Further reading is available
at the Pomerium [guides](https://www.pomerium.com/guides/) and
[references](https://www.pomerium.com/reference/) pages.
