module github.com/Cloud-Foundations/keymaster

go 1.21

toolchain go1.22.0

replace github.com/bearsh/hid v1.3.0 => github.com/bearsh/hid v1.5.0

require (
	github.com/Cloud-Foundations/Dominator v0.3.3
	github.com/Cloud-Foundations/golib v0.5.0
	github.com/Cloud-Foundations/npipe v0.0.0-20191222161149-761e85df1f92
	github.com/Cloud-Foundations/tricorder v0.0.0-20191102180116-cf6bbf6d0168
	github.com/aws/aws-sdk-go v1.51.21
	github.com/aws/aws-sdk-go-v2 v1.26.1
	github.com/aws/aws-sdk-go-v2/config v1.27.11
	github.com/aws/aws-sdk-go-v2/service/organizations v1.27.3
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.6
	github.com/bearsh/hid v1.5.0
	github.com/cloudflare/cfssl v1.6.5
	github.com/cviecco/argon2 v0.0.0-20171122181119-1dc43e2eaa99
	github.com/duo-labs/webauthn v0.0.0-20221205164246-ebaf9b74c6ec
	github.com/flynn/u2f v0.0.0-20180613185708-15554eb68e5d
	github.com/foomo/htpasswd v0.0.0-20200116085101-e3a90e78da9c
	github.com/howeyc/gopass v0.0.0-20210920133722-c8aef6fb66ef
	github.com/lib/pq v1.10.9
	github.com/marshallbrekka/go-u2fhost v0.0.0-20210111072507-3ccdec8c8105
	github.com/mattn/go-sqlite3 v1.14.22
	github.com/nirasan/go-oauth-pkce-code-verifier v0.0.0-20170819232839-0fbfe93532da
	github.com/pquerna/otp v1.4.0
	github.com/prometheus/client_golang v1.19.0
	github.com/tstranex/u2f v1.0.0
	github.com/vjeantet/ldapserver v1.0.1
	golang.org/x/crypto v0.22.0
	golang.org/x/net v0.24.0
	golang.org/x/oauth2 v0.19.0
	golang.org/x/term v0.19.0
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/square/go-jose.v2 v2.6.0
	gopkg.in/yaml.v2 v2.4.0
	mvdan.cc/sh/v3 v3.8.0
)

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/ProtonMail/go-crypto v1.0.0 // indirect
	github.com/acomagu/bufpipe v1.0.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.28.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.23.4 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/cyphar/filepath-securejoin v0.2.4 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.5.0 // indirect
	github.com/go-git/go-git/v5 v5.12.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/skeema/knownhosts v1.2.2 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	golang.org/x/sync v0.7.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)

require (
	github.com/GehirnInc/crypt v0.0.0-20230320061759-8cc1b52080c5 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.11 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.20.5 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dchest/blake2b v1.0.0 // indirect
	github.com/flynn/hid v0.0.0-20190502022136-f1b9b6cc019a // indirect
	github.com/fxamacker/cbor/v2 v2.6.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/certificate-transparency-go v1.1.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/lor00x/goldap v0.0.0-20180618054307-a546dffdd1a3 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.52.3 // indirect
	github.com/prometheus/procfs v0.13.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/time v0.5.0
	golang.org/x/tools v0.20.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce // indirect
)
