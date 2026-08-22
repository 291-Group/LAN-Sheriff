# The Dispatch, threat model and wire protocol

Section 11 records the design questions and how each was settled; section 12 records what the design does
and does not guarantee, including the gaps that remain open by choice.

The Dispatch lets separate LAN Sheriff installations pair with one another and share what each of them
sees, so that a network gets whole-LAN visibility without a SPAN port, a mirrored switch port, or the tool
running on the router. Why that matters is set out in [VANTAGE-POINTS.md](VANTAGE-POINTS.md); this document
is only about how to build it without making the product worse than not having it.

This is the one feature that opens a socket other machines connect to. Everything else in LAN Sheriff is
a reader: it watches, stores and displays. The Dispatch makes a security tool into a network service, and a
network service on a machine that holds a complete record of its network is exactly the thing an attacker
would most like to find.

---

## 1. What is being protected

In rough order of how bad it would be to lose:

| Asset | Why it matters |
|---|---|
| **The observation database** | Who talks to whom, when, and using which application. This is a behavioural profile of everyone on the network. It is more sensitive than most of the traffic it describes, because it is already indexed and summarized. |
| **The instance private key** | Whoever holds it can impersonate this instance to every peer it is paired with, and inject fabricated observations into their view. |
| **Availability of monitoring** | A monitor that can be silenced by a stranger is worse than no monitor, because its silence is read as "nothing is happening". |
| **The machine itself** | The Dispatch must never become a path to code execution, file access, or lateral movement. |

The realistic worst case is not subtle. It is: *an unauthenticated stranger on the network connects to the
Dispatch port and is handed a searchable history of every device in the house.*

---

## 2. Who the adversaries are

Enumerated deliberately, because a mitigation without a named adversary is decoration.

**A1, Unauthenticated attacker with LAN access.** The default assumption. Compromised IoT device, a guest
on the Wi-Fi, a neighbour who guessed the passphrase. Can connect to any open port, send arbitrary bytes,
spoof addresses, forge ARP and mDNS, and replay anything they have seen.

**A2, Attacker off the local network.** Reachable only if the port is exposed by port-forwarding, a
misconfigured firewall, or a bind to `0.0.0.0` on a machine with a public address. The mitigation is
primarily *not being reachable*, which is a configuration property and therefore ours to get right.

**A3, A compromised paired peer.** The most interesting adversary, and the one most protocol designs
ignore. Pairing is not a promise of good behaviour forever: the peer is a general-purpose computer that may
be compromised tomorrow. It holds a valid key and can say anything it likes within the protocol.

**A4, An attacker who obtains a join code.** Over a shoulder, in a screenshot, in a support ticket, in a
chat log. A join code is a bearer credential for the short window it is alive.

**A5, A passive eavesdropper on the LAN.** Wireless monitoring, a mirrored port, a compromised switch.
Sees everything on the wire but cannot necessarily inject.

**A6, An active on-path attacker during pairing.** Can intercept and modify the pairing exchange, which is
the single moment when trust is established from nothing. This is where most pairing schemes fail.

### Explicit non-goals

Stated so that nobody later believes the protocol offers them:

- **No defence against a compromised host OS.** If the machine running LAN Sheriff is owned, the database
  and key are readable and no protocol fixes that.
- **No anonymity or traffic-analysis resistance.** A watcher can tell that two instances are peered and
  roughly how much they exchange. Padding and cover traffic are not worth their cost here.
- **No NAT traversal, relaying, or internet rendezvous.** The Dispatch is a local-network protocol between
  machines the same person owns. There is no server, no broker, no hole-punching. This removes an entire
  category of attack by not building it.
- **No forward secrecy beyond what TLS 1.3 already provides**, which is ample.
- **No multi-user model.** Peers are machines, not accounts. There are no roles or permissions.

---

## 3. Trust boundaries

```
   ┌────────────────────────── this machine ───────────────────────────┐
   │                                                                   │
   │   capture ──▶ store ──▶ API ──▶ dashboard        (existing, trusted)
   │                 ▲                                                 │
   │                 │ writes namespaced by peer                       │
   │            ┌────┴─────┐                                           │
   │            │ Dispatch │◀══════ TLS 1.3, mutual auth ══════════════╪══▶ peer
   │            └──────────┘                                           │
   └───────────────────────────────────────────────────────────────────┘
                      ▲
                      └── everything arriving here is untrusted input,
                          including from a peer that authenticated correctly
```

The boundary that matters most is the inner one. **Authentication is not authorization, and authorization
is not truthfulness.** A peer that presents the right key has proven only that it is the machine we paired
with. It has not proven that its observations are real. Adversary A3 lives in that gap, and the merge rules
in §8 are the whole answer to it.

---

## 4. Design decisions

### D-1. Off until switched on, with nothing pre-created

No listener, no keypair, no certificate, no database table populated. Enabling is an explicit action.
**The keypair is generated on first enable, not at install**, an unused install should not have a private
key sitting on disk that could be stolen and later used to impersonate it once the feature is turned on.

### D-2. Binds to a specific local interface, never `0.0.0.0` by default

The listener binds to the address on the interface the user selected, and refuses to start on an interface
whose address is globally routable unless `--dispatch-allow-public` is passed. That flag prints a warning
naming the risk. This is the mitigation for A2, and it belongs in the code rather than in the documentation
where nobody will read it.

### D-3. TLS 1.3, mutually authenticated, with pinned self-signed certificates

The alternative was the Noise protocol framework, which is smaller on the wire and pleasant to reason about.
TLS wins here for reasons that follow the dependency policy of standard library first:

- `crypto/tls` is in the standard library, is TLS 1.3-only when configured that way, and is among the most
  scrutinized code Go ships. Noise would mean a third-party implementation plus hand-rolled framing,
  handshake state machine, and rekeying, all of it new code on the attack surface.
- Certificate *pinning* removes the part of TLS that is actually dangerous. There is no CA, no chain
  building, no name validation, no revocation, no trust store. `VerifyPeerCertificate` compares the
  presented public key against the exact key pinned at pairing and rejects everything else. `RootCAs` and
  `ClientCAs` are nil; `InsecureSkipVerify` is set precisely so the default verification is replaced, not
  weakened, and the custom callback is mandatory.
- Ed25519 keys, TLS 1.3 only, no session resumption or 0-RTT (0-RTT is replayable by construction and
  buys nothing on a LAN).

Certificates are self-signed wrappers around the identity key. The certificate is a container; **the pinned
public key is the identity**, and a certificate may be regenerated on expiry without re-pairing so long as
the key is unchanged.

### D-4. The identity is the key; the fingerprint is how a human checks it

Peer ID = the leading **125 bits** of SHA-256 over the SPKI-encoded public key, rendered in Crockford
base32 as exactly five groups of five characters. Displayed on both machines after pairing so an operator
can compare them.

125 rather than 128 because 128 bits is 26 base32 characters, which renders as five groups and a dangling
group of one, and a trailing single character is exactly what an eye skips when comparing two screens.
Three bits are a cheap price. This is an identifier, not a security control: nothing is authorized by a
matching peer ID, since authorization is the pinned key compared in full.

### D-5. Summaries, never raw flows

Peers exchange per-bucket aggregates only. This is a privacy decision first and a bandwidth decision second:
a raw flow log is a keystroke-level record of somebody's evening, while an hourly aggregate is what the
dashboard actually renders. Raw detail never leaves the machine that observed it. There is no
"request raw" message in v1, and a request channel of any kind is deliberately **deferred**, because it is a
data-exfiltration channel with a friendly name. It can be added later if a concrete need appears.

### D-6. A peer may only speak about itself

Every observation is stored namespaced under the reporting peer. A peer cannot report about devices
attributed to another peer, and cannot report about this machine. See §8.

---

## 5. Identity and pairing

Pairing is the only moment trust is created out of nothing, and A6 is on the wire while it happens.

### The join code

Instance **A** displays a code: **40 Crockford-base32 characters in 8 groups of 5**, carrying 200 bits.

| Field | Size | Purpose |
|---|---|---|
| Version | 4 bits | Protocol generation, so a stale code fails cleanly |
| Reserved | 4 bits | Zero; keeps the payload a whole number of bytes |
| Key tag | 64 bits | Truncated SHA-256 of A's SPKI public key |
| Secret | 128 bits | Single-use pairing secret, from `crypto/rand` |

Forty characters is long for something transcribed by hand, and the length was interrogated rather than
accepted. The secret cannot shrink (see below) and the tag turns out to earn its 64 bits, so the code
stays long. It is typed once per peer, and pairing offers copy-to-clipboard.

The code is valid for **fifteen minutes**, is **single-use**, and is invalidated when the pairing screen is
closed. A's address and port are shown alongside it as text, not encoded into it, because addresses change
and a code that embeds one becomes wrong the moment DHCP moves.

### Why both a secret and a key tag

The key tag alone is not enough: a public key is public, and A6 could present their own key and a matching
tag they computed. The secret alone is not enough either, because it must be transmitted over a channel the
attacker may control before any authenticated channel exists.

Together, and bound to the channel, they are sufficient:

1. **B** connects to A. TLS 1.3 completes with A's self-signed certificate; B does not yet trust it.
2. B checks the presented key against the tag from the code. A mismatch aborts immediately.
3. Both sides derive `binding = ExportKeyingMaterial("lan-sheriff/dispatch/pair/v1", 32)` from the
   completed TLS connection, a value unique to *this* TLS session that an on-path attacker cannot force to
   match on both of their separate connections.
4. B sends `pair_request` containing `HMAC-SHA256(secret, binding || B_pubkey)`.
5. A recomputes it. A mismatch aborts and **burns the code**.
6. A replies with `HMAC-SHA256(secret, binding || A_pubkey)`; B verifies.
7. Both pin the other's public key and persist the peer record. The code is consumed.

The channel binding in step 3 is what defeats A6. An attacker relaying between A and B has two distinct TLS
sessions with two distinct exporter values, so a proof captured from one is worthless in the other. This is
the same reasoning as TLS channel binding in SCRAM, and is the reason the scheme does not need a full PAKE.

A6 is thereby reduced to guessing a 128-bit secret within fifteen minutes, against a listener that burns the
code on the first bad attempt.

### Why the secret stays at 128 bits, and why the tag stays at all

Both were challenged on the grounds that an attacker gets essentially *one* online guess, which 64 bits
would already defeat. The reason both survive is the same, and it is not online guessing.

**A proof is an offline brute-force target.** `HMAC(secret, binding ‖ pubkey)` is computed over values the
recipient knows. An on-path attacker who receives a proof can grind the secret offline at their leisure, 
and if they recover it, they can complete a pairing later while the code is still live. Against an offline
search, 128 bits is the requirement and 64 would not do.

**The tag is what prevents the attacker from ever collecting one.** Step 2 has B verify the tag against the
presented key *before* sending anything. An attacker presenting their own key fails that check, and B
aborts having disclosed nothing. Without the tag the exchange would still be secure against completion, 
the attacker cannot forge A's reply, but B would have handed a stranger a grindable target first.

So the tag is not merely an early-abort convenience, which is how it was first described. It is what keeps
the offline attack from having any input at all.

### Verified, not assumed

The scheme rests on specific behaviour of Go's TLS, so it was proven with a spike before being written
down here rather than after somebody had built on it:

| Claim | Result |
|---|---|
| Ed25519 self-signed certificates complete a mutually authenticated TLS 1.3 handshake | ✅ |
| `VerifyPeerCertificate` pinning rejects an unpinned key **during the handshake** | ✅ rejected as `unpinned peer key`, before any application byte |
| `ExportKeyingMaterial` yields the identical value on both ends | ✅ |
| A second session yields a **different** binding | ✅, this is the property the whole anti-MITM argument depends on |
| The HMAC proof verifies against the other side's independently derived binding | ✅ |
| A proof captured from one session fails in another | ✅, A6 defeated |

The last two rows are the ones that mattered. Had the exporter been stable across sessions, or unavailable
on a resumed one, the pairing design would have needed a full PAKE instead.

### Constant time and rate limits

All comparisons use `crypto/subtle.ConstantTimeCompare`. Pairing accepts one attempt per code, and the
pairing listener accepts at most one connection at a time.

### Unpairing

Removes the pinned key and every observation attributed to that peer. Unilateral and immediate; the other
side discovers it on next connection. There is no negotiated teardown, because an attacker should never be
able to *prevent* an unpair.

---

## 6. Transport and framing

- TLS 1.3 only. `MinVersion = MaxVersion = VersionTLS13`. Cipher suites left to Go's defaults, which for
  1.3 are all acceptable.
- Mutual authentication: `ClientAuth = RequireAnyClientCert`, with the pinning callback doing the real work.
- **An unpaired connection is closed before a single application byte is parsed.** Pinning is enforced in
  the handshake callback, so a stranger's connection dies in the handshake and never reaches the decoder.
- One long-lived connection per peer. The instance with the lexicographically lower peer ID dials; the other
  listens. If both dial simultaneously, the connection from the lower ID wins and the other is closed, 
  a deterministic rule that avoids a duel.

### Frames

```
┌──────────────┬───────────────────────────┐
│ length (u32) │ payload (JSON, length b.) │
└──────────────┴───────────────────────────┘
```

Big-endian length prefix. **`maxFrame = 1 MiB`, checked before allocating anything.** A larger declared
length closes the connection; it is never trusted enough to size a buffer. This is the single most common
way a framed protocol becomes a memory-exhaustion bug.

JSON via `encoding/json`, stdlib, debuggable with `tcpdump` on a test rig, and the volumes involved are
small. Unknown fields are **ignored, not rejected**, so a newer peer can add fields without breaking an
older one. Unknown *message types* are ignored with a log line, for the same reason.

### Resource limits, all enforced

| Limit | Value | Against |
|---|---|---|
| Frame size | 1 MiB | Memory exhaustion |
| Handshake timeout | 10 s | Slow-loris (A1) |
| Idle timeout | 90 s | Dead connections held open |
| Read/write deadline per frame | 30 s | Stalled peers |
| Messages per second, per peer | 20, token bucket | Flooding by A3 |
| Buckets per `summary` | 1,500 | Oversized merges |
| Concurrent connections | 1 per peer, 8 total | Connection exhaustion |
| Pending pairing connections | 1 | Pairing brute force (A4/A6) |

Every limit is a constant with a comment naming the adversary it exists for.

---

## 7. Messages

All messages share an envelope:

```json
{ "v": 1, "type": "hello", "body": { } }
```

**`hello`**, first message in both directions. Carries protocol version, instance ID, software version,
capability flags, and the sender's clock. If the peer's `v` is unsupported, the connection closes with a
`bye`; there is no downgrade path below the minimum supported version.

**`summary`**, the payload that matters. A list of buckets, at most 1,500 per message.

The ceiling is derived from the frame limit rather than chosen: a bucket with every string at its maximum
encodes to about 562 bytes, so 1,500 of them fit inside 1 MiB with room to spare, and a test fails if the
two limits ever stop agreeing. A sender with more to report sends several messages; buckets are upserted by
key, so splitting a report changes nothing.

```json
{ "hour": 1753977600, "device": "<peer-local device id>",
  "endpoint_org": "Cloudflare, Inc.", "endpoint_country": "US", "asn": 13335,
  "app": "Firefox", "proto": "tcp", "port": 443,
  "flows": 42, "bytes_out": 91234, "bytes_in": 882101 }
```

Note what is *not* here: no destination IP, no hostname, no timestamps finer than an hour, no process
paths. An organization and a country are what the Watchtower draws.

**`finding`**, a Wanted List finding from the peer: rule code, subject, score, and the same thin `detail`
map the notifier sends. Rendered with the peer's name attached.

**`device`**, roster entries: peer-local device ID, label, type, vendor, first/last seen. No MAC address in
v1; a MAC is a durable cross-network identifier and the roster does not need one from a peer.

**`ping` / `pong`**, liveness, with the sender's clock for skew tracking.

**`bye`**, orderly close with a reason code. Advisory only; a connection may vanish without one, and the
code must handle that identically.

---

## 8. Merging, and the compromised peer

This section is the answer to A3, and it is the part that is easy to get wrong by being too trusting of
something that authenticated successfully.

**Rule 1, everything is namespaced by reporter.** Every row written from a peer carries `peer_id`. There
is no unattributed data in the store. The Watchtower's layer control is a filter over this column,
which is why attribution has to exist at write time rather than being reconstructed later.

**Rule 2, a peer may only speak about itself.** A `summary` or `device` message is accepted only for
devices in that peer's own namespace. A peer cannot report observations attributed to another peer, and
cannot report about this machine. A compromised peer can therefore lie *about itself*, which is
unavoidable, since it is the only witness to its own traffic, but cannot fabricate evidence against a
different machine. This single rule contains the blast radius of a compromise to the compromised machine.

**Rule 3, peer data is a cache, never a source of truth.** It carries a TTL and is dropped when the peer
is unpaired or suspended. This instance's own observations are never overwritten, corrected, or merged into
by a peer.

**Rule 4, suspend without unpairing.** A peer may be marked *suspended*: the connection stays, the data
stops being merged and stops being displayed. This exists because the useful response to "this peer is
behaving strangely" is to stop believing it while continuing to observe it, which unpairing prevents.

**Rule 5, peer timestamps are advisory.** Clamped to `[now - 48h, now + 5m]`. A peer cannot write into the
future to pin itself to the top of a timeline, nor backdate to slip beneath a retention boundary. Skew
beyond 5 minutes is surfaced in the UI rather than silently corrected, because a wrong clock on a security
tool is itself worth knowing about.

**Rule 6, the peer's own scoring is not trusted as ours.** A `finding` from a peer is displayed as *that
peer's* finding, attributed by name. It never contributes to this instance's suspicion scores. Otherwise a
compromised peer could drive a device's score by assertion.

---

## 9. Failure, which is the normal case

A peer is a laptop that closes. Disappearing is ordinary behaviour, not an error, and the demand from the
plan is that a vanished peer "greys out; it never blocks, stalls or crashes the others."

- **All peer I/O is off the request path.** No API handler ever waits on a peer. The dashboard renders from
  the local store, always, and peer data is whatever has already been merged.
- **Reconnect with exponential backoff and jitter**: 1s doubling to 5m, ±20%. Jitter matters because two
  instances rebooting together otherwise synchronize into a lockstep retry.
- **Grey, then stale, then cold.** No contact for 90s greys the peer; its data is marked stale after one
  hour and dropped at TTL. The UI distinguishes "this peer is gone" from "this peer reports nothing", which
  are opposite facts that look identical if handled carelessly.
- **A peer that misbehaves is disconnected, not crashed on.** Malformed frame, oversized length, unknown
  version, rate limit exceeded: log, close, back off. Every decoder path returns an error; none panics. The
  frame decoder gets a fuzz target.
- **Bounded queues, drop-oldest.** Same discipline as the existing WebSocket hub: a slow peer degrades its
  own view and never applies backpressure to capture.

---

## 10. Storage and key handling

- Private key in `dispatch/identity.key`, `0600`, in the data directory, written atomically. Permissions
  verified on load; a world-readable key refuses to load rather than being silently used.
- Peer records (pinned public key, name, trust state, last seen) in SQLite, in new append-only migrations.
- The key is never logged, never exposed through the API, and never included in an export. Only the
  fingerprint is.
- Wiping data (the existing Settings action) removes peer observations but **not** pairings, because
  re-pairing every machine after clearing a database would be a hostile surprise. Unpairing is its own,
  separate action.

---

## 11. Design questions, and how each was settled

Kept because a future change should have to argue against the reasoning rather than rediscover it.

1. **Is the truncated 64-bit key tag long enough?** Its job is to stop an attacker's key passing B's check,
   so forging it means finding a public key whose SPKI digest collides on 64 bits: around 2⁶⁴ work for a
   *targeted* second preimage, not a birthday collision, since the target is fixed by the code already
   displayed. **Settled: 64 bits.**
2. **Should `finding` messages exist at all?** They are the most useful thing to share and the most
   attacker-controllable. **Settled: yes, confined to display-only by Rule 6.** A peer's finding is shown
   as that peer's, attributed by name, and never contributes to this instance's own scoring.
3. **TTL for peer data.** Peer data is a cache, not a record. **Settled: 7 days**, matching the existing
   rollup retention, so there is one number to reason about rather than two.
4. **Does pairing need its own port?** A separate port is cleaner to reason about, and is also a second
   thing to firewall and a second thing to get wrong. **Settled: the same port, distinguished by message
   type** — the listener reads `pair_request` where a session would send `hello`.
5. **Peer count ceiling.** **Settled: 8**, chosen to bound resource use rather than from any requirement.
   It is a constant, and raising it is a one-line change with a measurable cost.

## 12. What is and is not guaranteed

Written at review, because "is it secure" is not answerable without saying *against what*. Everything below
is a statement about the design as built, not an aspiration.

### Guaranteed

- **End-to-end encrypted, with no third party by construction.** TLS 1.3 directly between the two machines.
  There is no relay, no broker, no rendezvous server and no NAT traversal, not as a matter of configuration
  but because none exists in the code. Nobody is in the middle to be compromised, subpoenaed, or breached.
- **Mutually authenticated against a pinned key.** Both ends verify; there is no CA to mis-issue and no name
  to spoof. An unpaired connection dies inside the handshake, before a single application byte is parsed.
- **Forward secrecy**, from TLS 1.3's ephemeral key exchange. Recording the traffic today and stealing a key
  tomorrow does not decrypt it.
- **No replay across sessions.** 0-RTT and session resumption are disabled; 0-RTT data is replayable by
  construction and buys nothing on a LAN.
- **A compromised peer cannot implicate another machine.** It may lie about itself, unavoidable, it is the
  only witness to its own traffic, but the schema namespaces every row by reporter, so there is no statement
  it can make that reaches another peer's data or this instance's own.
- **A peer cannot redirect us.** It may advertise a port; the host always comes from the connection already
  held. It cannot point this instance at a third party.
- **Minimum disclosure on the wire.** Summaries carry an organization and a country, never an address, a
  hostname, a looked-up domain, or anything about an individual connection. A test fails if a field is added.

### Not guaranteed, deliberately

- **The database is not encrypted at rest.** It is `0600`, owned by the account running LAN Sheriff, a
  and set explicitly rather than left to the process umask. But file permissions are not encryption: anyone who can become that user, or read the disk
  offline, can read the observation history. Encrypting it would mean a key, and a key that must be present
  for an unattended service to start is stored next to the data it protects. That trade is not obviously
  worth making, and pretending otherwise would be worse than saying so.
- **No defence against a compromised host.** If the machine is owned, the database and the identity key are
  readable and no protocol fixes that.
- **No traffic-analysis resistance.** An observer on the LAN can tell that two instances are peered and
  roughly how much they exchange. Padding and cover traffic are not worth their cost here.
- **No protection against a malicious operator.** Somebody with access to the dashboard can pair, unpair and
  read everything. The dashboard's own password is the control, not this protocol.
- **The beacon reveals that something is beaconing.** Fifteen bytes on a multicast group: a hash and a port.
  An observer learns a LAN Sheriff may be present. They do not learn which instance, what it is called, or
  who it is paired with.

### Reviewed and found adequate

The pairing exchange was the part most worth attacking, and it holds: the key tag denies an on-path attacker
any proof to grind offline, the channel binding makes a captured proof useless outside its own TLS session,
the mutual proof stops a relay completing the exchange, and the window burns on the first failure by two
independent mechanisms. 128 bits against an offline search, one guess against an online one.
