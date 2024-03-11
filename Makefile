# Set GOPATH to a sensible default if not already set.
ifdef USERPROFILE
GOPATH ?= $(USERPROFILE)\go
else
GOPATH ?= $(HOME)/go
endif


# This is how we want to name the binary output
BINARY=keymaster

# These are the values we want to pass for Version and BuildTime
VERSION=1.15.1
#BUILD_TIME=`date +%FT%T%z`

# keymaster client requires special tags on linux
#EXTRA_BUILD_FLAGS 
ifneq ($(OS),Windows_NT)
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		EXTRA_BUILD_FLAGS+= -tags=hidraw
	endif
endif


# Setup the -ldflags option for go build here, interpolate the variable values
#LDFLAGS=-ldflags "-X github.com/ariejan/roll/core.Version=${VERSION} -X github.com/ariejan/roll/core.BuildTime=${BUILD_TIME}"

all:	init-config-host cmd/keymasterd/binData.go
	cd cmd/keymaster; go install ${EXTRA_BUILD_FLAGS} -ldflags "-X main.Version=${VERSION}"
	cd cmd/keymasterd; go install -ldflags "-X main.Version=${VERSION}"
	cd cmd/keymaster-unlocker; go install -ldflags "-X main.Version=${VERSION}"
	cd cmd/keymaster-eventmond;  go install -ldflags "-X main.Version=${VERSION}"

build:	cmd/keymasterd/binData.go
	go build ${EXTRA_BUILD_FLAGS} -ldflags "-X main.Version=${VERSION}" -o bin/   ./...

cmd/keymasterd/binData.go:
	-go-bindata -fs -o cmd/keymasterd/binData.go -prefix cmd/keymasterd/data cmd/keymasterd/data/...

win-client: client-test
	 go build -ldflags "-X main.Version=${VERSION}" -o bin .\cmd\keymaster\

client-test:
	go test -v  ./cmd/keymaster/...

get-deps:	init-config-host
	go get -t ./...

clean:
	rm -f bin/*
	rm -f keymaster-*.tar.gz

init-config-host:
	@test -f cmd/keymaster/config_host.go || (cp -p templates/config_host_go cmd/keymaster/config_host.go && echo 'Created initial cmd/keymaster/config_host.go')

${BINARY}-${VERSION}.tar.gz:
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

test:	init-config-host
	make -f makefile.certs
	go test ./...

verbose-test:	init-config-host
	go test -v ./...

format:
	gofmt -s -w .

format-imports:
	goimports -w .
