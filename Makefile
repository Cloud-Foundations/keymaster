# Set GOPATH to a sensible default if not already set.
ifdef USERPROFILE
GOPATH ?= $(USERPROFILE)\go
else
GOPATH ?= $(HOME)/go
endif


# This is how we want to name the binary output
BINARY=keymaster

# These are the values we want to pass for Version and BuildTime
VERSION?=1.17.1
DEFAULT_HOST?=
VERSION_FLAVOUR?=
EXTRA_LDFLAGS?=
PRINTVERSION=${VERSION}
ifneq ($(VERSION_FLAVOUR),)
PRINTVERSION=${VERSION}-${VERSION_FLAVOUR}
endif
DEFAULT_LDFLAGS=-X main.Version=${PRINTVERSION} ${EXTRA_LDFLAGS}
CLIENT_LDFLAGS=${DEFAULT_LDFLAGS} -X main.defaultHost=${DEFAULT_HOST}
#BUILD_TIME=`date +%FT%T%z`

# keymaster client requires special tags on linux
EXTRA_BUILD_FLAGS?=
ifneq ($(OS),Windows_NT)
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		EXTRA_BUILD_FLAGS+= -tags=hidraw
	endif
	CLIENT_DEST?="./cmd/keymaster/"
	OUTPUT_DIR?=bin/
else
	CLIENT_DEST?=".\\\\cmd\\\\keymaster\\\\"
	OUTPUT_DIR?=bin\\
endif


# Setup the -ldflags option for go build here, interpolate the variable values
#LDFLAGS=-ldflags "-X github.com/ariejan/roll/core.Version=${VERSION} -X github.com/ariejan/roll/core.BuildTime=${BUILD_TIME}"

all:	install-client
	cd cmd/keymasterd; go install -ldflags "${DEFAULT_LDFLAGS}"
	cd cmd/keymaster-unlocker; go install -ldflags "${DEFAULT_LDFLAGS}"
	cd cmd/keymaster-eventmond;  go install -ldflags "${DEFAULT_LDFLAGS}"

build:	prebuild
	go build ${EXTRA_BUILD_FLAGS} -ldflags "${CLIENT_LDFLAGS}" -o $(OUTPUT_DIR) ./...


keymaster.spec:
    ifeq ($(OS), Windows_NT)
		powershell -Command "Get-Content keymaster.spec.tpl | ForEach-Object { \$$_.Replace('{{VERSION}}', '$(VERSION)') } | Set-Content keymaster.spec"
    else
		sed 's/{{VERSION}}/$(VERSION)/g' keymaster.spec.tpl > keymaster.spec;
    endif

prebuild: keymaster.spec

install-client:	prebuild
	cd cmd/keymaster; go install ${EXTRA_BUILD_FLAGS} -ldflags "${CLIENT_LDFLAGS}"

build-client:	prebuild
	go build -ldflags "${CLIENT_LDFLAGS}" -o $(OUTPUT_DIR) $(CLIENT_DEST)

win-client: client-test
	 go build -ldflags "${CLIENT_LDFLAGS}" -o $(OUTPUT_DIR) .\cmd\keymaster\

client-test:
	go test -v  ./cmd/keymaster/...

get-deps:
	go get -t ./...

clean:
	rm -f bin/*
	rm -f keymaster-*.tar.gz
	rm -f keymaster.spec

${BINARY}-${VERSION}.tar.gz:	prebuild
	mkdir ${BINARY}-${VERSION}
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" lib/ ${BINARY}-${VERSION}/lib/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" cmd/ ${BINARY}-${VERSION}/cmd/
	rsync -av  misc/ ${BINARY}-${VERSION}/misc/
	rsync -av proto/ ${BINARY}-${VERSION}/proto/
	rsync -av keymasterd/ ${BINARY}-${VERSION}/keymasterd/
	rsync -av eventmon/ ${BINARY}-${VERSION}/eventmon/
	cp -p LICENSE Makefile keymaster.spec README.md go.mod go.sum ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/

rpm:	${BINARY}-${VERSION}.tar.gz
	rpmbuild -ta ${BINARY}-${VERSION}.tar.gz

tar:	${BINARY}-${VERSION}.tar.gz

test:
	make -f makefile.certs
	go test ./...

verbose-test:
	go test -v ./...

format:
	gofmt -s -w .

format-imports:
	goimports -w .
