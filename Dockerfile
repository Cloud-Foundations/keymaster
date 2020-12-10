#################
# Build Step
#################

FROM golang:latest as build

# Setup work env
RUN mkdir -p /app/ /tmp/gocode/src/github.com/Cloud-Foundations/keymaster
ADD . /tmp/gocode/src/github.com/Cloud-Foundations/keymaster
WORKDIR /tmp/gocode/src/github.com/Cloud-Foundations/keymaster


# Required envs for GO
ENV GOPATH=/tmp/gocode
ENV DEBIAN_FRONTEND=noninteractive

# Update and confirm deps
RUN apt-get update && apt-get -y dist-upgrade && apt-get -y install build-essential

# Install deps
RUN make get-deps

## Dirty Hack - Remove when https://github.com/golang/go/issues/37278 is closed
# Compatibility with OpenSSH 8.2 and above
WORKDIR /tmp/gocode/src/golang.org/x/crypto/
RUN git config user.email "you@example.com"
RUN git config user.name "Your Name"
RUN git pull --no-edit https://go.googlesource.com/crypto refs/changes/37/220037/3
WORKDIR /tmp/gocode/src/github.com/Cloud-Foundations/keymaster
## Dirty Hack End

# Build and copy final result
RUN make

#################
# Run Step
#################

FROM debian:buster as run

# Copy binary from build container
COPY --from=build /tmp/gocode/bin/keymasterd /app/keymasterd
COPY --from=build /tmp/gocode/bin/keymaster-unlocker /app/keymaster-unlocker
COPY --from=build /tmp/gocode/src/github.com/Cloud-Foundations/keymaster/cmd/keymasterd/customization_data /usr/share/keymasterd/customization_data
COPY --from=build /tmp/gocode/src/github.com/Cloud-Foundations/keymaster/cmd/keymasterd/static_files /usr/share/keymasterd/static_files

# Copy docker specific scripts from build container
COPY --from=build /tmp/gocode/src/github.com/Cloud-Foundations/keymaster/misc/docker/start.sh /app/docker/

# Perform update and clear cache
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get -y --no-install-recommends install procps apache2-utils ca-certificates dumb-init
RUN apt-get -y dist-upgrade && rm -rf /var/cache/apt/*


# Install init

# Expose web and LDAP ports
EXPOSE 80 443 6920

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/bin/sh", "/app/docker/start.sh"]
