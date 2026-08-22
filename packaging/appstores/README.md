# App-store manifests

Four self-hosting platforms, each wanting the same information in its own
format. These files are the source of truth; submitting to a store means opening
a pull request against that store's repository with the relevant one.

| file | platform | submitted to |
|---|---|---|
| `umbrel-app.yml` + `umbrel-docker-compose.yml` | Umbrel | `getumbrel/umbrel-apps` |
| `casaos-app.json` | CasaOS | `IceWhaleTech/CasaOS-AppStore` |
| `runtipi-config.json` | Runtipi | `runtipi/runtipi-appstore` |
| `unraid-lan-sheriff.xml` | Unraid | `Squidly271/community.applications` |

## The two things every one of them has to say

**Host networking is required.** A container on a bridge watches Docker's own
virtual network. The dashboard comes up, the Roster fills with other containers,
and the map stays empty. Somebody would reasonably conclude the app is broken.
Every manifest here sets it and every description says why.

**A server is not a vantage point.** These platforms run on a box sitting on the
LAN, not between the LAN and the internet, so Patrol Mode sees that box's traffic
and broadcast and very little else. That is not a bug and the dashboard says so,
but a store listing that promised whole-network visibility would generate a
stream of reports that the app does not work. The descriptions name the
limitation rather than letting somebody find it.

## Submitting

The image is published at `ghcr.io/291-group/lan-sheriff` and
`291group/lan-sheriff`. Check that the version in each manifest matches the
release being submitted before opening a pull request.

Umbrel and CasaOS both want screenshots. Use ones generated from
`scripts/demoseed`, never a real network.
