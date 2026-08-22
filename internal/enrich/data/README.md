# Embedded enrichment datasets

This directory is where `make datasets` vendors the GeoIP and ASN databases that
get baked into a release binary, so that a freshly installed LAN Sheriff paints
the Watchtower **offline, on first run, with no key and no setup**.

The databases themselves are deliberately **not committed**. They are ~4 to 5 MB
each, they are republished monthly, and git is the wrong place for them. A fresh
checkout therefore contains only this file, which also guarantees the `go:embed`
pattern always matches something and the build never breaks for want of a
download.

## Files placed here by `make datasets`

| File | Source | Size |
|---|---|---|
| `dbip-country-lite.mmdb` | DB-IP Lite Country | ~9 MB uncompressed |
| `dbip-asn-lite.mmdb` | DB-IP Lite ASN | ~12 MB uncompressed |

The city database (~150 MB uncompressed) is never embedded. It is fetched at
runtime only when the user opts in.

## Behaviour without them

Nothing breaks. If a build carries no embedded database, LAN Sheriff fetches
what it needs into the data directory in the background on first run, a few
seconds of "locating…" on the map, and nothing thereafter. If that fetch also
fails (no internet), endpoints simply appear without a location or an
organisation, and everything else works.

## Licence and attribution

The DB-IP Lite databases are licensed **CC BY 4.0**. Shipping them obliges us to
attribute DB-IP in the application UI *and* in the README, and both do. Do not
ship a binary embedding these files without the attribution in place.

<https://db-ip.com/db/lite.php>
