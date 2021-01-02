# LDAP

If you use LDAP as your authoritative source of users, you can have keymaster
use this for both password and userinfo.

## Keymaster config.yml

1. Enable LDAP for user authentication

```
ldap:
  bind_pattern: "cn=%s,ou=People,dc=example,dc=com"
  ldap_target_urls: "ldaps://ldaps.example.com:636"
  disable_password_cache: false
```

2. Configure LDAP userinfo_sources

```
  ldap:
    bind_username: "cn=keymaster,ou=serviceacct,dc=example,dc=com"
    bind_password: "MyBindPw"
    group_prepend: ""
    ldap_target_urls: "ldaps://ldaps.example.com:636"
    user_search_base_dns: ["dc=example,dc=com"]
    user_search_filter: "(&(objectClass=posixAccount)(uid=%s))"
    group_search_base_dns: ["dc=example,dc=com"]
    group_search_filter: "(&(objectClass=posixGroup)(memberUid=%s))"
```

Set a group_prepend item, such as ```ldap-``` if you utilize both gitdb and LDAP

**WARNING** Keymaster only supports ldaps and will not allow unencrypted LDAP
requests.
