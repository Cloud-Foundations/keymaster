# HUProxy

## What is HUProxy

[HTTP(S)-Upgrade Proxy](https://github.com/google/huproxy) — Tunnel anything
(but primarily SSH) over HTTP websockets.

This example uses Ubuntu 20.04 as a base.

## HUProxy Config

1. On a build machine with go installed run 
```CGO_ENABLED=0 go get github.com/google/huproxy```. Copy that binary to your
target in ```/usr/local/bin```

2. Create a system user named huproxy place
```/etc/systemd/system/huproxy.service``` with the following contents.

```
[Unit]
Description=Simple ssh proxy
After=network.target

[Service]
Type=simple
User=huproxy
Group=huproxy
WorkingDirectory=/tmp
ExecStart=/usr/local/bin/huproxy -listen [::1]:8086
Restart=on-failure
PrivateTmp=true

[Install]
WantedBy=default.target
```

3. Run ```systemctl daemon-reload && systemctl enable --now huproxy```.

## Apache Config

1. Install Apache and stop it

```
$ sudo apt update && sudo apt -y install apache2 && systemctl stop apache2
```

2. Remove existing configuration

```
$ sudo rm -rf /etc/apache2/mods-enabled/* /etc/apache2/sites-enabled/*
```

3. Enable required modules

```
$ sudo a2enmod mpm_event proxy_wstunnel ssl rewrite access_compat authz_core

```

4. Obtain the Keymaster CA file

```
$ sudo curl -Lo /etc/apache2/keymaster-ca.pem https://keymaster.example.com/public
/x509ca
```

5. Place this in ```/etc/apache2/sites-available/zerotrust.conf```. Be sure to
swap in your personal SSL certificates.

```
<VirtualHost *:80>
        ServerName sshproxy.example.com
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        RewriteEngine On
        RewriteCond %{REQUEST_URI} !^/.well-known/acme-challenge [NC]
        RewriteCond %{HTTPS} !=on
        RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R=301,L]
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<IfModule mod_ssl.c>
        <VirtualHost _default_:443>
                Protocols http/1.1
                ServerName sshproxy.example.com
                ServerAdmin webmaster@localhost
                DocumentRoot /var/www/html
                ErrorLog ${APACHE_LOG_DIR}/error.log
                CustomLog ${APACHE_LOG_DIR}/access.log combined
                SSLEngine on
                SSLProtocol -all +TLSv1.3 +TLSv1.2
                SSLHonorCipherOrder off
                SSLSessionTickets off
                SSLCipherSuite "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
                SSLCertificateFile     /etc/ssl/certs/ssl-cert-snakeoil.pem
                SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

                SSLCACertificateFile /etc/apache2/keymaster-ca.pem
                SSLUserName SSL_CLIENT_S_DN_CN
                SSLVerifyClient require

                ProxyRequests Off
                ProxyPass "/proxy/" "ws://[::1]:8086/proxy/"

                # Default Deny
                <LocationMatch "^/proxy/">
                        Order Allow,Deny
                        Deny from all
                </LocationMatch>

                # Example with group limit. You can even use ldap groups.
                #<LocationMatch "^/proxy/adminbastion.internal.example.com/22">
                #       Allow from all
                #       AuthGroupFile /etc/apache2/groups
                #       Require group admin
                #</LocationMatch>

                # Allow TCP port 22
                <LocationMatch "^/proxy/[^/]+/22$">
                        Allow from all
                </LocationMatch>

        </VirtualHost>
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

**Do not enable http2 until this [issue](https://github.com/gorilla/websocket/issues/417) is resolved.**

6. Enable zerotrust.conf and start Apache

```
$ sudo a2ensite zerotrust && sudo systemctl start apache2
```

## SSH Config

1. On a build machine with go installed run 
```CGO_ENABLED=0 go get github.com/google/huproxy/huproxyclient```. Copy that binary to your
target in ```/usr/local/bin```

2. Place your config in ```/etc/ssh/ssh_config``` or in individual users ```~/.ssh/config```.

```
Host *.internal.example.com
    ProxyCommand /usr/local/bin/huproxyclient -key ~/.ssl/keymaster.key -cert ~/.ssl/keymaster.cert wss://sshproxy.example.com/%h/%p  
```

## Congrats
You can now ssh to internal servers without a VPN.
