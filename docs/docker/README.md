# Keymaster in Docker

## Build

On a machine with docker installed, pull this source and create the container

```
$ git clone https://github.com/Cloud-Foundations/keymaster.git
$ cd keymaster
$ docker build -t local/keymaster .
```

## Bootstrap

Now that you have the local container built, you will need to create keys and a
default config for bootstrapping the server.

```
$ cd misc/docker
$ cp env.example .env    # Edit this file to set timezone and local dirs
$ . .env
$ docker run --rm -it -v "${KEYMASTER_DATA}/conf/:/etc/keymaster/" -v \
 "${KEYMASTER_DATA}/db/:/var/lib/keymaster/" -e  "TZ=${TIMEZONE}" \
 local/keymaster /app/keymasterd -generateConfig
```

This will generate a series of prompts. Here's how to answer them.


Enter and re-enter your passphrase

```
Please enter your passphrase:

Please re-enter your passphrase:
```

Due to a bug in config, enter / for Base dir

```
Default base Dir[/tmp]:/
```

Leave blank and hit enter for data directory

```
Data Directory[//var/lib/keymaster]:
```

Enter your public hostname

```
HostIdentity[keymaster.DOMAIN]:keymaster.mydomain.com
```

Hit enter for the ports and accept the default.

```
HttpAddress[:443]:
AdminAddress[:6920]:
```

Fix the config issues mentioned in the main README.md

```
$ sudo sed -i 's% data_directory:.*% data_directory: "/var/lib/keymaster"%g' \
 ${KEYMASTER_DATA}/conf/config.yml
$ sudo sed -i 's% shared_data_directory:.*% shared_data_directory: "/usr/share/keymasterd/"%g' \
 ${KEYMASTER_DATA}/conf/config.yml
```

## Start

After bootstrapping configs and keys you just start the container. This will
start it sealed.

```
$ docker-compose up -d
```

## Unseal

By default the CA will start in a sealed state. To unseal it you will need to
enter your passphrase.

```
$ docker exec -e SSL_CERT_FILE=/etc/keymaster/server.pem -it keymaster \
  /app/keymaster-unlocker -cert /etc/keymaster/adminClient.pem \
  -key /etc/keymaster/adminClient.key -keymasterHostname localhost
Password for unlocking localhost: 
OK
```

## Add users

By default a user is created. Let's start by deleting this and creating our own
user.

```
$ rm -f ${KEYMASTER_DATA}/conf/passfile.htpass
$ docker exec -it keymaster /usr/bin/htpasswd -B -c \
 /etc/keymaster/passfile.htpass $USERNAME
```

## Add users

By default a user is created. Let's start by deleting this and creating our own
user.

```
$ rm -f ${KEYMASTER_DATA}/conf/passfile.htpass
$ docker exec -it keymaster /usr/bin/htpasswd -B -c \
 /etc/keymaster/passfile.htpass $USERNAME
```

## SSH

Distribute the SSH CA to hosts

```
${KEYMASTER_DATA}/conf/masterKey.asc.pub -> destination:/etc/ssh/masterKey.asc.pub
```
Configure sshd to trust the CA by adding this line to ```/etc/ssh/sshd_config```

```
TrustedUserCAKeys /etc/ssh/masterKey.asc.pub
```

SSH will allow clients who have run the keymaster client to login.

**NOTE** Username must match principal on all hosts or you will need to
configure AuthorizedPrincipalsFile.

## X509 Certs

The CA for X509 certificates is available via
https://keymaster.example.com/public/x509ca for download
