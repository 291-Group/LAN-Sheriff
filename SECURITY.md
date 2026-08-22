# Security Policy

## Reporting a vulnerability

Report privately to **info@291group.com**, or via GitHub's private vulnerability reporting on
[291-Group/LAN-Sheriff](https://github.com/291-Group/LAN-Sheriff/security/advisories/new). Please don't open
a public issue for a security problem.

Include what you did, what happened, and what you expected. A rough proof of concept, the output of
`lan-sheriff version`, and the operating system are usually enough. If you cannot tell whether something is
a vulnerability or a limitation, report it anyway and say which you think it is.

### What happens next

| | |
|---|---|
| **Within 3 working days** | We acknowledge the report and say who is handling it. |
| **Within 10 working days** | We tell you whether we can reproduce it, what we think the severity is, and whether we consider it in scope. |
| **Within 90 days** | We aim to ship a fix. If it will take longer we say so, with a reason and a new date, rather than going quiet. |
| **On release** | A GitHub advisory is published with the details and, unless you would rather not be named, credit to you. |

We ask that you give us those 90 days before publishing. If a fix is ready sooner the advisory goes out
sooner, and there is no interest in sitting on one. If we have gone quiet past a date we gave you, publish;
a maintainer who stops answering has forfeited the request.

This is a small project and there is **no bug bounty**. Saying so plainly is fairer than letting anyone spend
a weekend on it expecting otherwise. What we can offer is credit, a fast answer, and a fix.

### Safe harbour

We will not pursue or support legal action against anyone who reports a vulnerability in good faith and
follows the rules below. Research within them is authorized, and if a third party comes after you for it, we
will say so on the record.

- **Test against an installation you own.** For this tool in particular that is not a formality: it watches a
  network, so pointing your research at somebody else's is the thing the misuse section further down is about.
- Do not access, alter or keep anyone else's data. If you come across some, stop and tell us.
- Do not degrade service for anyone, and do not run automated scans against machines that are not yours.
- Give us the time above before going public.

### In scope

The binary, the dashboard, the API, The Dispatch protocol, the install and uninstall scripts, the packaging,
and the release pipeline. Anything that lets somebody reach data on a machine running LAN Sheriff, or reach
the machine itself, is worth reporting.

### Out of scope

- **The vantage-point limitation.** On a switched network LAN Sheriff sees this machine's traffic and
  broadcast, and nothing else, unless it is placed somewhere that sees more. That is a property of switched
  ethernet, it is documented in [docs/VANTAGE-POINTS.md](docs/VANTAGE-POINTS.md), and the dashboard says so.
- **Anything already requiring administrative access to the machine.** Somebody who is root has better options
  than this program, and the misuse section explains why.
- **The domestic case in the misuse section.** Somebody with physical access installing this on a household
  member's computer is a real harm and it is discussed honestly below. It is a limit of what any local
  software can prevent, not a defect we can patch, and reports of it will be answered with that section.
- Missing hardening on a loopback-only bind where no data crosses a trust boundary.
- Dependency advisories with no demonstrated path through this code. `govulncheck` runs on every push, and
  reachability is what we act on.
- Output from an automated scanner with no working demonstration of impact.

## What LAN Sheriff does and does not do

This is a **defensive visibility tool for networks you own or administer**. Understanding its posture is
part of understanding its security properties:

- **It observes. It never modifies.** No blocking, dropping, injecting, rewriting, or proxying of traffic in
  any mode. It is not a firewall, an ad-blocker, or a DNS sink.
- **No payload storage.** Packet payloads are never written to disk. Patrol Mode parses a few plaintext
  application signals (DNS names, TLS SNI, HTTP Host) purely to label a connection, and stores only the
  labels. **There is no packet export**: nothing in this product writes a payload
  anywhere, so there is no stored packet data to disclose, subpoena or leak.
- **No TLS interception.** No certificate injection, no decryption, ever.
- **No active exploitation.** The optional per-device port scan is a light, explicit, user-initiated action
  on a single chosen device. Nothing scans automatically or aggressively.
- **Local only.** No cloud service, no account, no telemetry, no phone-home, no update check. All observations
  stay in the local data directory, and your traffic is never uploaded.

Four things do leave the machine, and the complete list is also stated in the app's own Help, because a claim
nobody can check is worth nothing:

| | |
|---|---|
| Location and domain databases | Ordinary file downloads on a schedule. The provider learns that somebody fetched a file, and nothing about your network. |
| This network's public address | Looked up once, so the map has an origin to draw from. Disable with `--locate=false`. |
| **Registration lookups** | **The exception.** Opening an endpoint and asking who owns it sends *that address* to IANA and then to the governing regional registry, so those two learn which endpoint you were reading about. On demand only, once per endpoint, never on a timer or in the background. |
| Notifications and The Dispatch | Nothing at all unless you configure them, and then only to the destination you chose. |

`--offline` stops the first three outright. The fourth never starts on its own: notifications need a
destination you configured, and The Dispatch needs a peer you paired. Note that passing `--dispatch`
alongside `--offline` still starts peer sharing, because serving a stored record and sharing summaries are
separate choices rather than one.

## Privileges

- **Deputy Mode** (the default) needs no elevated privileges. It reads this machine's own socket tables.
- **Patrol Mode** needs packet-capture privilege (`CAP_NET_RAW` on Linux, BPF device access on macOS, Npcap
  on Windows). It is opt-in, and its absence is never fatal, the app falls back to Deputy Mode.

Run with the least privilege that gives you what you need. Granting capture privilege to a long-running
process is a real decision; the app is designed so you can decline it and still get value.

## Network exposure

- The default bind is `127.0.0.1:2911` with no password, on the assumption that anyone who can reach loopback
  is already you. A dashboard nothing else can reach is already private, and a password there would be
  friction with no benefit.
- On a loopback bind, requests whose `Host` header does not name this machine are **refused**. Without that
  guard, a page on the internet can point a hostname it controls at `127.0.0.1` and have your own browser read
  the dashboard on its behalf. The browser sits inside the trust boundary even though the attacker does not.
- **Binding to any other address requires a password.** The first visitor must create one before anything is
  shown. It is stored as a bcrypt hash, `0600`, in the data directory, beside the data rather than in a config
  file. Login exchanges it for a session cookie that is `HttpOnly` and `SameSite=Strict`.
- The first visitor to reach a network-bound dashboard is the one who sets the password, so **set it
  immediately** after starting on a network address. Until it is set, the install is unclaimed, and on an
  untrusted network that is a window worth closing quickly.
- Five failed logins from one address lock that address out for fifteen minutes. The limit keys on the host
  and not the host and port, so opening a fresh connection does not reset it.
- `--allow-insecure` serves to the network with no password at all. It is for deployments where something
  else already authenticates: a tailnet, or a reverse proxy that requires a login of its own.
- `--require-password` demands one even on a loopback bind, which is what you want on a machine other people
  can log in to.
- `--trusted-host` names an additional `Host` value to accept on a loopback bind, which is what a proxy in
  front (`tailscale serve`, nginx, Caddy) needs in order not to be refused by the rebinding guard. Exact names
  only: no wildcards and no suffix matching, because the `Host` header is chosen by whoever is calling.
- LAN Sheriff does not terminate TLS. If you expose it beyond a trusted network, put it behind Tailscale or a
  reverse proxy that does. [docs/REMOTE-ACCESS.md](docs/REMOTE-ACCESS.md) covers the arrangements that work.

## Data sensitivity

The database is a detailed record of your network's behaviour: which devices exist, which apps run, what
they connect to, and what domains get resolved. Treat it as sensitive. It lives in the data directory with
restrictive permissions, and the UI provides a one-click wipe.

## Dependency advisories

`govulncheck` runs in CI on every push and reports **zero** vulnerabilities this
code can reach. `npm audit` on the frontend reports zero.

One line in `govulncheck -show verbose` is worth explaining, for anyone who runs
it themselves and reads past the summary. [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)
says `golang.org/x/crypto/openpgp` is unmaintained and should not be used. This
project does not import it. The only thing used from that module is
`golang.org/x/crypto/bcrypt`, for hashing the dashboard password, which the
advisory does not cover. It has no fixed version because it is not a defect to
be patched: upstream is telling people to stop using a package we never started
using.

## Supported versions

The latest minor release receives security fixes. Older minor releases do not, so the fix for a reported
vulnerability will always be an upgrade rather than a backport.

## Misuse: could this be used to watch somebody else?

Yes, and pretending otherwise would be dishonest. This section says what is and
is not possible, because a monitoring tool that will not discuss its own misuse
is not one to trust.

### The remote-attacker version is weak

Turning LAN Sheriff into remote spyware requires code execution and persistence
on the target machine, and root or Administrator for Patrol Mode. **Anyone who
has that already has better options.** As an implant this is poor: no command
and control, no persistence mechanism, no evasion, a large binary, and it opens
a web server on the machine it is hiding on.

Peer sharing is also awkward to abuse at a distance. It is off until `--dispatch`
is passed. It refuses to listen on any address that is not private unless
`--dispatch-allow-public` is *also* passed. Pairing needs a code displayed on one
machine and typed into the other inside five minutes. Doing that remotely means
already controlling the machine and seeing its screen, at which point the
pairing is the least of the owner's problems.

### The version that is real

Somebody with **physical access** installs it on a partner's, housemate's or
child's computer and pairs it with their own on the same network. Local-network
pairing is a security property everywhere else, and here it is exactly what makes
this the easy case. No software running on a machine can prevent its owner-in-fact
from doing this.

What LAN Sheriff does instead:

- **Sharing is visible on every screen.** The line at the foot of the dashboard
  changes from "LAN Sheriff stays on this machine" to "Shared only with N
  machines you paired". It cannot be dismissed and it is not in a settings page.
- **`lan-sheriff status` answers from a terminal**, with no privilege, no running
  instance and no password. It names every paired machine and when the pairing
  happened.
- **The pairing ledger outlives the pairing.** Unpairing deletes the peer and
  everything it reported, and deliberately does not delete the record that it
  happened. A machine with nothing paired today can still show that it was paired
  last month.
- **A peer receives aggregates only**, a device, an organization, a country, an
  application and counts, by hour. Never addresses, never hostnames, never the
  domains that were looked up, never an individual connection.

The ledger is append-only by convention, not by trigger. Anyone who can drop a
trigger can drop a table, and pretending otherwise would be theatre. It raises
the effort from clicking *unpair* to knowing the schema and editing the database,
which is the honest limit of what local storage can offer.

### What it cannot do at all

- **It cannot modify, block or redirect traffic.** Capture is passive. There is
  no code path that writes a packet, drops one, or answers on behalf of anything.
- **It cannot read encrypted content.** It sees who a device talks to and how
  much, never what was said.
- **It cannot see another device's traffic without a vantage point.** That means
  running on the router or on a mirror port, a physical change to how the
  network is wired, not something arranged remotely.

### If you found this running on your computer

Run `lan-sheriff status`. It will tell you whether anything is paired, what was
paired historically, and how long the machine has been observed. If the answer is
not what you expected, the database is a single file in the data directory and
deleting it removes everything recorded.
