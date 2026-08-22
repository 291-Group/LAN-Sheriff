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
FROM node:20-alpine AS web
WORKDIR /src
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
COPY internal/web/ /src/../internal/web/
RUN npm run build

# ---- binary ------------------------------------------------------------------
# Patrol Mode needs libpcap, which needs cgo, so this cannot be a cross-compile
# from an alien architecture. Buildx runs this stage natively per platform.
FROM golang:1.25-bookworm AS build
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
ARG LIBPCAP=1.10.5
RUN wget -q "https://www.tcpdump.org/release/libpcap-${LIBPCAP}.tar.gz" \
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
        -X github.com/291-Group/LAN-Sheriff/internal/cli.Commit=${COMMIT}" \
      -o /out/lan-sheriff ./cmd/lan-sheriff \
 && ldd /out/lan-sheriff | grep -q libpcap \
    && { echo "libpcap is still linked dynamically" >&2; exit 1; } || true

# ---- runtime -----------------------------------------------------------------
# debian-slim rather than distroless or alpine. Alpine is musl and this binary
# is glibc; distroless would work but makes it harder for somebody to open a
# shell and see what the thing is doing, which for a tool that watches a network
# is a property worth keeping.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
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
