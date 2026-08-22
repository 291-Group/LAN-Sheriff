module github.com/291-Group/LAN-Sheriff

go 1.25.5

// **The build toolchain, pinned as a floor rather than left to the machine.**
//
// go1.25.5 carries twelve reachable standard-library advisories, two of them in
// crypto/tls, which is what The Dispatch uses for every peer connection. CI
// happened to be clean because `go-version: '1.25'` resolves to the newest
// patch, but anyone building from source got whatever their machine had, and
// the beta binaries handed out on 5 August were built on 1.25.5 for exactly
// that reason.
//
// Raised to 1.25.13 on 14 August for five more, again reachable rather than
// theoretical: a post-handshake message limit in crypto/tls, an asn1 recursion
// depth reached through x509 key parsing at startup, quadratic path resolution
// in net/url, a missing ReadHeaderTimeout on the h2c check in net/http, and an
// idna label rejection. The first two sit directly under The Dispatch.
//
// A `toolchain` line makes the requirement the module's rather than the
// builder's: any go command will fetch this version or newer before building.
// A floor, not a pin, so security patches are still picked up automatically.
// It is also what makes the fix reach anyone building from source, which is
// every user until the packaged release exists.
toolchain go1.25.14

require (
	github.com/coder/websocket v1.8.15
	github.com/gopacket/gopacket v1.7.1
	github.com/oschwald/maxminddb-golang/v2 v2.5.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.55.0
	golang.org/x/net v0.58.0
	golang.org/x/sys v0.47.0
	modernc.org/sqlite v1.57.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	golang.org/x/mod v0.40.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	modernc.org/libc v1.75.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.0 // indirect
)
