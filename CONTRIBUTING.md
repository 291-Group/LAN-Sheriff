# Contributing

Thank you for looking. This file is short on ceremony and specific about the few things that are genuinely
unusual here, because those are what a first pull request tends to trip over.

## Getting it running

```sh
git clone https://github.com/291-Group/LAN-Sheriff
cd LAN-Sheriff
make build        # builds the dashboard and the binary
./lan-sheriff serve
```

`make build` needs Go 1.25 and Node 20. Packet capture is behind a build tag, because it needs cgo and a
libpcap, and the default build stays cgo-free so that cross-compiling to a Raspberry Pi and `go install` both
remain trivial:

```sh
make patrol       # Patrol Mode, needs libpcap (Linux, macOS) or Npcap (Windows)
```

Most work does not need it. The dashboard, the rules, the storage and every view run in Deputy Mode.

## Before you open a pull request

```sh
make check
```

That is exactly what CI runs: `go vet`, staticcheck over the whole module, the tests, and the repository checks
that no compiler enforces. If it passes here it passes there, and if it does not, that is a bug in `make check`
worth reporting on its own.

## The things that are actually different here

**Comments explain why, not what.** The code says what it does. A comment earns its place by recording the
thing that is not visible: the alternative that was tried and failed, the platform that behaves differently,
the bug this shape prevents. There are comments in this repository longer than the function beneath them, and
they are the ones most worth keeping.

**Every user-visible string is translated into all twelve languages.** English, French, Spanish, German,
Portuguese, Russian, Chinese, Japanese, Hindi, Bengali, Arabic and Hebrew. The type checker fails on a missing
key, and `scripts/check-i18n.mjs` catches the subtler damage: Latin text spliced into a non-Latin catalogue by
a careless bulk edit. Commands, flags, file paths and product names stay untranslated, because they are typed
rather than read.

**Two of those languages are written right to left.** Use `padding-inline-start` rather than `padding-left`,
`inset-inline-end` rather than `right`, and check Arabic before claiming a layout works.

**Backend prose is never sent to the browser.** The server has no idea what language the reader uses, so
anything destined for a person travels as a stable code and is rendered on the client. `scripts/check-msg-codes.mjs`
fails if a code has no translation.

**Canadian English, and no em dashes.** Both are enforced by review rather than by a script, except in the
no-JS page, where a test checks the dashes.

## Where things live

| Path | What is in it |
|---|---|
| `cmd/lan-sheriff` | The entry point, and nothing else |
| `internal/capture` | Deputy Mode (socket tables) and Patrol Mode (packet capture) |
| `internal/pipeline` | Turning observations into flows and endpoints |
| `internal/store` | SQLite, migrations, and every query |
| `internal/suspicion` | The rules behind the Wanted List |
| `internal/dispatch` | Peer sharing: identity, pairing, transport, protocol |
| `internal/api` | The HTTP API |
| `web/src` | The dashboard, Preact and TypeScript |
| `docs/` | The Dispatch threat model and wire protocol, remote access, vantage points |

## Reporting a security issue

Please do not open a public issue. [SECURITY.md](SECURITY.md) says how to reach us.

## Licence

By contributing you agree that your contribution is licensed under the AGPL-3.0-or-later, the same licence as
the project.
