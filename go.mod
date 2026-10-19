module github.com/291-Group/LAN-Sheriff

go 1.26.0

// **The build toolchain, pinned as a floor rather than left to the machine.**
//
// A `toolchain` line makes the Go version the module's requirement rather than
// the builder's: any go command fetches this version or newer before building.
// A floor, not a pin, so later security patches are still picked up. It is also
// what carries the fix to anyone building from source, which is every user
// until a packaged release exists.
//
// History, because each bump here has been a real advisory rather than a
// version-chasing habit:
//   - go1.25.14 originally, for a run of reachable standard-library advisories,
//     two of them in crypto/tls, which The Dispatch uses for every peer
//     connection.
//   - Raised to go1.27.2 on 18 October 2026 for GO-2026-6617: an HPACK encoder
//     race that crashes the net/http HTTP/2 server, reachable through the
//     dashboard's own server per govulncheck. Fixed in the standard library at
//     go1.26.9; go1.27.2 is the current release carrying it. The module half of
//     the same advisory is golang.org/x/net, raised below to v0.60.0.
//
// The `go` directive is 1.26.0 because golang.org/x/net v0.60.0 requires it;
// the toolchain above is what actually builds.
toolchain go1.27.2

require (
	github.com/coder/websocket v1.8.15
	github.com/gopacket/gopacket v1.7.4
	github.com/oschwald/maxminddb-golang/v2 v2.8.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
	modernc.org/sqlite v1.60.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
