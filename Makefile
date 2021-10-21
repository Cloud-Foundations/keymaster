# Set GOPATH to a sensible default if not already set.
ifdef USERPROFILE
GOPATH ?= $(USERPROFILE)\go
else
GOPATH ?= $(HOME)/go
endif


# This is how we want to name the binary output
BINARY=keymaster

# These are the values we want to pass for Version and BuildTime
VERSION=1.9.1
#BUILD_TIME=`date +%FT%T%z`

# Setup the -ldflags option for go build here, interpolate the variable values
#LDFLAGS=-ldflags "-X github.com/ariejan/roll/core.Version=${VERSION} -X github.com/ariejan/roll/core.BuildTime=${BUILD_TIME}"

all:	init-config-host keymasterd-bin-data
	cd $(GOPATH)/src; go install -ldflags "-X main.Version=${VERSION}" github.com/Cloud-Foundations/keymaster/cmd/*

keymasterd-bin-data:
	-go-bindata -fs -o cmd/keymasterd/binData.go -prefix cmd/keymasterd/data cmd/keymasterd/data/...

win-client:
	cd $(GOPATH)\src && go install -ldflags "-X main.Version=${VERSION}" github.com\Cloud-Foundations\keymaster\cmd\keymaster
	cd $(GOPATH)\src\github.com\Cloud-Foundations\keymaster\cmd\keymaster && go test -v ./...

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
	cp LICENSE Makefile keymaster.spec README.md ${BINARY}-${VERSION}/
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
