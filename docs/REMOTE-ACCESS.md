# Reaching the dashboard from somewhere else

LAN Sheriff listens on `127.0.0.1:2911` and nothing else. That is the whole configuration for most people, and
this document is for the ones it does not suit: you run it on a home server or a Raspberry Pi and you want to
look at it from a laptop, or from outside the house.

The short version is that **Tailscale is the right answer** and everything else on this page is a trade you
should make deliberately.

## The default, and what it is buying you

A dashboard nothing else can reach is already private. There is no password on a loopback bind because anyone
who can reach loopback is already sitting at the machine, and a password there would be friction with no
benefit. That is what lets the app promise zero configuration honestly.

One thing does happen on a loopback bind, and it is worth knowing about because it can look like a bug.
Requests whose `Host` header does not name this machine are refused with `403 forbidden: unexpected Host
header`. Without that check, a page on the internet can point a hostname it controls at `127.0.0.1` and have
your own browser fetch the dashboard and hand it over. This is DNS rebinding, and the reason it works is that
the browser is inside the trust boundary even though the attacker is not. It costs nothing to close, so it is
closed.

That guard is why a proxy in front of a loopback bind needs one extra flag. See below.

## The options, ranked

| | Reachable from | Encrypted | Password | Effort |
|---|---|---|---|---|
| **Tailscale** | your devices only | yes, by Tailscale | optional | small |
| **LAN bind** | anyone on your network | **no** | required | none |
| **Reverse proxy** | wherever you point it | yes, by the proxy | proxy's or ours | moderate |
| **Port forwarding** | the entire internet | no | required | do not |

## Tailscale

Tailscale puts your machines on a private network of their own, reachable from your devices and nothing else.
Nothing is exposed to the internet, and you do not open a port on your router. For a tool that holds a
detailed record of your network, that is the difference that matters.

Install Tailscale on the machine running LAN Sheriff and on whatever you want to look at it from, then pick
one of the two arrangements below.

### Bind to the tailnet address

The simplest thing that works. Find the machine's tailnet address with `tailscale ip -4`; it will be in
`100.64.0.0/10`.

```sh
lan-sheriff serve --listen 100.101.102.103:2911
```

This is not a loopback bind, so **a password is required**: the first visitor is asked to create one before
anything is shown. Open it at `http://100.101.102.103:2911`, or at the machine's MagicDNS name if you have
MagicDNS on.

Set the password immediately. Until it is set, the install is unclaimed, and whoever reaches it first is the
one who claims it.

Traffic between your devices is encrypted by Tailscale itself, so the plain `http://` here is not what it
looks like. It is not encrypted **on the machine's own loopback interface**, which does not matter, and it is
encrypted over every hop between devices, which does.

### Put `tailscale serve` in front, for HTTPS

If you want a real certificate and an `https://` address, keep LAN Sheriff on loopback and let Tailscale
terminate TLS in front of it.

```sh
lan-sheriff serve --trusted-host machine.tailnet-name.ts.net
tailscale serve --bg 2911
```

The `--trusted-host` flag is not optional here, and leaving it out is the single most likely thing to go wrong
on this page. A proxy forwards the browser's original `Host` header, so the request arrives at the loopback
bind naming `machine.tailnet-name.ts.net`, the rebinding guard does not recognise it, and **every request
returns 403**. Naming the host tells the guard that this one is yours.

Use the machine's full MagicDNS name, which `tailscale status` will show you. The flag is repeatable if the
machine answers to more than one name. It accepts exact names only: no wildcards, no suffix matching, because
the attacker is the one who chooses the `Host` header and a pattern would give back the thing being guarded.

The `tailscale serve` syntax has changed across releases, so check `tailscale serve --help` on the version you
have rather than trusting the line above.

One warning. `tailscale funnel` is not `tailscale serve`. Funnel publishes to the **entire internet**, and
pointing it at LAN Sheriff would put a record of your network behind nothing but a password. Do not.

## A reverse proxy

The same shape as `tailscale serve`, with the same requirement. nginx, Caddy and Traefik all forward the
original `Host` by default, so a loopback bind behind any of them needs the name declared:

```sh
lan-sheriff serve --trusted-host sheriff.example.com
```

Caddy, which will get a certificate on its own:

```
sheriff.example.com {
    reverse_proxy 127.0.0.1:2911
}
```

nginx, which needs both blocks below and will half-work without the second:

```nginx
location / {
    proxy_pass http://127.0.0.1:2911;

    # Forward the original name rather than rewriting it to 127.0.0.1. Two
    # separate things depend on this: the rebinding guard matches it against
    # --trusted-host, and the live feed is a WebSocket whose same-origin check
    # compares the browser's Origin against this header. Rewrite it and the
    # dashboard loads but never updates.
    proxy_set_header Host $host;

    # The upgrade itself. WebSockets need HTTP/1.1 and these two headers, and
    # the long timeout stops a quiet connection being cut every 60 seconds.
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 24h;
}
```

If the proxy already requires a login of its own, and only then, `--allow-insecure` will stop LAN Sheriff
asking for a second one.

## On the LAN, with a password

No tunnel, no proxy. Bind to the machine's LAN address:

```sh
lan-sheriff serve --listen 192.168.1.10:2911
```

A password is required, and the first visitor creates it.

Be clear about what this does not give you. The connection is **plain HTTP over your network**, so anyone in a
position to watch that network sees the dashboard's contents and, at login, your password. On a home network
you control that may be an acceptable trade. On a shared flat, an office, or any network with guests on it, it
is not, and one of the arrangements above costs very little more.

## Do not forward a port

Do not put LAN Sheriff on the internet by forwarding a port on your router. A password and a lockout are not
what stands between a public service and the people who scan for them, and the thing behind this one is a
detailed record of every device in your home and everywhere they connect. Tailscale removes the reason to
consider it.

## The Dispatch across networks

Peer sharing has its own listener and its own address, so it needs its own decision. Over a tailnet:

```sh
lan-sheriff serve --dispatch --dispatch-listen 100.101.102.103:2912
```

The Dispatch refuses to bind an address reachable from the internet unless you pass
`--dispatch-allow-public`. Tailnet addresses are not, and are accepted without it. If you find yourself
reaching for that flag to get past a refusal, stop and read the address again: the flag really does permit an
internet-reachable bind, and once it is in a systemd unit or a compose file it stays there.

Pairing is unchanged over a tailnet. The Dispatch pins each peer's key on first pairing and every connection
after that is authenticated against it, so it does not rely on the network being trustworthy. Tailscale is
carrying the packets, not vouching for anybody.

## Checking it worked

The startup banner states what it did, and it is worth reading rather than assuming:

```
     reachable   anything that can reach this host on the network
     password    not set yet, open the dashboard to create one
```

`lan-sheriff status` reports the same from another terminal without needing a password.

Two failures account for nearly all of them:

**Everything returns 403 through a proxy.** The `Host` header is not one the guard recognises. Add
`--trusted-host` with the exact name in the browser's address bar.

**The dashboard loads but never updates.** The live feed is a WebSocket and the proxy is not carrying it. Either
the upgrade headers are missing, or the proxy rewrote the `Host` header, which makes the socket's same-origin
check fail even though the page itself loaded. See the nginx block above.
