# Keymaster as openid conect server

Keymaster supports working as an openid connect server using the code flow. For this clients are configured with a secret. A `default_email_domain` entry is used to create email addresses for users when the userinformation source (such as ldap) does not resolve the email.

## Client configuration

For each client there are 3 required fields and one optional.
```
client_id: required
client_secret: required
allowed_redirect_url_re: optional
allowed_redirect_domains: required
```
The `client_id` contains the string used to identify the openid/oauth client. This value is revealed to aplications so that is it not considered secret. The `client_secret` is used to verify the client. Must be kept secret. `allowed_redirect_url_re` is an array of regular expressions to evaluate the redirect_url of the server.
`allowed_redirect_domains`: is an array of domains or hostnames allowed to use this client_id. It is required.

For example a valid client configuration snippet would look like:
```
openid_connect_idp:
  default_email_domain: "example.com"
  clients:
     - client_id: "generic-example.com"
       client_secret: "supersecret1"
       allowed_redirect_domains:
           - "example.com"
     - client_id: "nakedGun"
       client_secret: "ILoveIt"
       allowed_redirect_url_re:
           - "^https://?[^/]*[.]example[.](com|net):?[0-9]*/"
       allowed_redirect_domains:
           - "example.com"
           - "example.net"

```
With this configuration any Https host with on the domain example.com would be able to use the idp with client_id `generic_example.com` And hosts in example.com and example.net would be able to use the client_id `nakedGun`
