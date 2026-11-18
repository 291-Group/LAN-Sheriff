# LAN Sheriff in a container.
#
# The interesting decisions are in docker-compose.yml, not here: a network
# monitor in a bridged container watches Docker's own virtual network and
# reports almost nothing, which is the containerised form of the vantage-point
# problem the whole product is careful about. This file just produces a small
# image with packet capture compiled in.

# ---- dashboard ---------------------------------------------------------------
# Built first and separately: it changes on its own schedule and its own cache
# layer keeps a Go-only edit from reinstalling node_modules.
FROM node:26-alpine AS web
WORKDIR /src
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
COPY internal/web/ /src/../internal/web/
RUN npm run build

# ---- binary ------------------------------------------------------------------
# Patrol Mode needs libpcap, which needs cgo, so this cannot be a cross-compile
# from an alien architecture. Buildx runs this stage natively per platform.
FROM golang:1.27-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential flex bison wget \
    && rm -rf /var/lib/apt/lists/*

# **libpcap is built here rather than installed, and the reason is dbus.**
#
# Debian's libpcap.a is compiled with D-Bus, Bluetooth and USB backends, so
# linking it statically fails on undefined dbus symbols. The obvious flags for
# static linking therefore do nothing useful: the build succeeds, the linker
# quietly prefers the shared object, and the result needs libpcap installed
# wherever it runs, which defeats the point of a static build.
#
# Built with the optional backends off, the archive links cleanly and the binary
# depends on nothing but libc.
# 1.10.7 (September 2026) closed seven CVEs in the BPF interpreter and the
# offline filter, after 1.10.6 closed an out-of-bounds read and write in
# address parsing. The archive is checked against the hash of the tarball whose
# signature was verified against The Tcpdump Group's release key, because a
# download that is linked into every Linux binary is not something to take on
# trust from whatever a mirror answers with that day.
ARG LIBPCAP=1.10.7
ARG LIBPCAP_SHA256=0b394ac90dbc0a9838ff97468e05c9c9a3e873dec2514cd58db65d859d296e31
RUN wget -q "https://www.tcpdump.org/release/libpcap-${LIBPCAP}.tar.gz" \
 && echo "${LIBPCAP_SHA256}  libpcap-${LIBPCAP}.tar.gz" | sha256sum -c - \
 && tar xzf "libpcap-${LIBPCAP}.tar.gz" \
 && cd "libpcap-${LIBPCAP}" \
 && ./configure --disable-dbus --disable-bluetooth --disable-usb --disable-rdma \
      --disable-shared --without-libnl >/dev/null \
 && make -j"$(nproc)" >/dev/null && make install >/dev/null \
 && cd .. && rm -rf "libpcap-${LIBPCAP}"*

WORKDIR /src

# Modules first, so dependency downloads survive a source edit.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# The dashboard from the stage above, replacing whatever was committed.
COPY --from=web /internal/web/dist ./internal/web/dist

ARG VERSION=docker
ARG COMMIT=unknown
# The commit count, which the release binaries carry and the image did not:
# every container footer read "build 0", which is the one number a bug
# report needs. Passed in by the workflow; a local build shows 0 honestly.
ARG BUILD=0
# The archive by absolute path, not -lpcap. gopacket declares its own
# `#cgo LDFLAGS: -lpcap`, which the linker resolves to the shared object if one
# exists; naming the file leaves it nothing to choose.
#
# libc stays dynamic on purpose. A fully static glibc binary breaks name
# resolution, and this program resolves names.
RUN CGO_ENABLED=1 CGO_LDFLAGS="/usr/local/lib/libpcap.a" \
    go build -tags patrol \
      -ldflags "-s -w \
        -X github.com/291-Group/LAN-Sheriff/internal/cli.Version=${VERSION} \
        -X github.com/291-Group/LAN-Sheriff/internal/cli.Commit=${COMMIT} \
        -X github.com/291-Group/LAN-Sheriff/internal/cli.Build=${BUILD}" \
      -o /out/lan-sheriff ./cmd/lan-sheriff \
 && ldd /out/lan-sheriff | grep -q libpcap \
    && { echo "libpcap is still linked dynamically" >&2; exit 1; } || true

# ---- runtime -----------------------------------------------------------------
# debian-slim rather than distroless or alpine. Alpine is musl and this binary
# is glibc; distroless would work but makes it harder for somebody to open a
# shell and see what the thing is doing, which for a tool that watches a network
# is a property worth keeping.
FROM debian:trixie-slim AS runtime
# The base image is rebuilt by Debian on its own schedule, and the packages it
# ships with (perl, util-linux, openssl, zlib) collect CVEs between rebuilds that
# nothing in this image ever executes but every scanner reports. Upgrading at
# build time means each release carries whatever Debian had fixed that day,
# whichever base image the builder happened to have cached.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
      ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/lan-sheriff /usr/local/bin/lan-sheriff

RUN mkdir -p /data

# **Runs as root inside the container, and that is the deliberate choice.**
#
# The first version set file capabilities and ran as an unprivileged user, which
# is the better-looking answer and does not work: a binary carrying file
# capabilities cannot be executed at all when those capabilities are absent from
# the container's bounding set. `docker run` with no flags produced
# "operation not permitted" and exit 1, rather than the Deputy Mode that needs
# no privilege whatsoever. An image that refuses to start unless you already
# know which flags to pass is a worse failure than the one it was avoiding.
#
# Root here is root in a namespace, and the compose file drops every capability
# except the two that packet capture actually requires. Without them the process
# simply runs in Deputy Mode and says so, which is the same behaviour as
# anywhere else.

VOLUME ["/data"]
EXPOSE 2911

# 0.0.0.0 inside the container, not because binding wide is good, but because a
# container's loopback is not the host's: bound to 127.0.0.1 here the dashboard
# would be unreachable even from the machine running it. The compose file uses
# host networking, so this is the host's own interface and the password gate
# applies exactly as it does outside a container.
ENV LAN_SHERIFF_DATA_DIR=/data
ENTRYPOINT ["lan-sheriff"]
CMD ["serve", "--listen", "0.0.0.0:2911", "--open=false"]
