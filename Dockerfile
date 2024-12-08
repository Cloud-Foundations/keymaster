#################
# Build Step
#################
FROM golang:bookworm as build

# Setup work env
RUN mkdir -p /app/ /tmp/gocode/src/github.com/Cloud-Foundations/keymaster
ADD . /tmp/gocode/src/github.com/Cloud-Foundations/keymaster
WORKDIR /tmp/gocode/src/github.com/Cloud-Foundations/keymaster

# Required envs for GO
ENV GOPATH=/tmp/gocode
ENV DEBIAN_FRONTEND=noninteractive

# Update and confirm deps
RUN apt-get update && apt-get -y dist-upgrade && apt-get -y install build-essential

# Build and copy final result
RUN make
RUN strip /tmp/gocode/bin/keymaster*

#################
# Run Step
#################
FROM debian:bookworm as run

# Copy binary from build container
COPY --from=build /tmp/gocode/bin/keymasterd /app/keymasterd
COPY --from=build /tmp/gocode/bin/keymaster-unlocker /app/keymaster-unlocker
COPY --from=build /tmp/gocode/src/github.com/Cloud-Foundations/keymaster/cmd/keymasterd/customization_data /usr/share/keymasterd/customization_data
COPY --from=build /tmp/gocode/src/github.com/Cloud-Foundations/keymaster/cmd/keymasterd/static_files /usr/share/keymasterd/static_files

# Perform update and clear cache
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get -y --no-install-recommends install procps apache2-utils ca-certificates dumb-init
RUN apt-get -y dist-upgrade && rm -rf /var/cache/apt/*

# Expose web and LDAP ports
EXPOSE 80 443 6920

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/app/keymasterd", "-config", "/etc/keymaster/config.yml", "-alsoLogToStderr"]
