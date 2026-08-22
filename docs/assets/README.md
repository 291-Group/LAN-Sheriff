# Assets

Everything here is generated from a **synthetic network**, never from a real one.

`scripts/demoseed` builds an invented household: nine devices, a television that
beacons to its manufacturer, a printer that speaks plain HTTP. The instance
serving it runs with `--offline`, so nothing about the machine doing the
recording is captured into the database.

That is deliberate. A real instance is somebody's home: device names, internal
addressing, the places they actually connect to, and, through the map origin,
roughly where they live. None of it belongs in a public README, and redacting
after the fact is a job that gets done correctly four times out of five.

## What is here

| file | what it shows |
|---|---|
| `watchtower.gif` | The map filling as traffic arrives. Recorded on the 24h range so the timeline reads as a histogram rather than one bar. ~11s |
| `walkthrough.gif` | Every view in turn, recorded live: the map draws, its counters climb as connections arrive, the DNS feed gains rows. ~31s |
| `walkthrough.mp4` | The tour, then pairing, then the peer's destinations on the map. In that order, because the peer layer is the result of the pairing. ~56s |
| `peering.gif` | Pairing end to end: the code shown, typed on the other machine, connected, and the peer's destinations appearing |
| `view-watchtower.jpg` | The map, with the destinations panel beside it |
| `view-chatter.jpg` | Radio Chatter: the DNS stream |
| `view-precinct.jpg` | The Precinct Map: devices in the middle, organizations around the outside |
| `view-roster.jpg` | The Roster: the devices, with type, address and maker |
| `view-wanted.jpg` | The Wanted List: the television beaconing to its manufacturer at a regular interval |
| `view-pairing.jpg` | The pairing code on screen, with the address under it |
| `view-peers.jpg` | Two machines paired: the peer's destinations in purple beside this machine's |

Two recordings rather than one, on purpose: the map filling up is the thing worth
leading with, and clicking through the views is a different sentence.

## How they are made

Everything is driven through Chrome's DevTools protocol against a headless
browser. Views are reached by clicking elements on the page rather than by
setting the URL, because the peer layer is component state rather than a route.

Motion matters more than it looks: `Page.startScreencast` streams frames as the
page paints while `demoseed -live` keeps dripping connections into the database
underneath, so the counters climb because connections are arriving and the map
redraws because there is something new to draw. Frames arrive only when the page
paints, so each frame's wall-clock time is recorded and used as its duration;
assembling at a fixed rate turns a quiet view into a flash.

The stills are 1568x774 and 110 to 190 KB each, which is why they are JPEG. The
README renders them at 820px, so that is roughly 1.9x and stays sharp on a
retina display. The recordings are kept at the capture resolution of 1397x880
with a full 256-colour palette: a 1000px version at 128 colours is 40% smaller
and visibly worse, and the small text in the destinations panel is most of what
the recording is showing.

The banner saying "Nothing is being captured" is left showing throughout. It is
true, and dismissing it would be a click made purely to tidy up a screenshot.

## Two things to check before publishing a re-recording

**No pointer in frame.** The capture draws a cursor even though the clicks are
synthetic. It is removed from every frame afterwards, which the flat map
background makes clean. It is easy to stop seeing, so look for it.

**No filesystem paths.** The Settings panel prints the path the database is
stored in, so whatever directory the demo instance runs from appears in every
frame showing that panel. It is the one place in the product that displays a
path. Run the demo from `/tmp/lan-sheriff-demo`, which says nothing about the
machine that made the recording, and check the Settings frames.

## Reproducing

Two instances, both `--offline` so neither records the machine doing the
recording, paired with each other so the peer views have something in them:

```sh
go run ./scripts/demoseed -out /tmp/lan-sheriff-demo/a -days 5
go run ./scripts/demoseed -out /tmp/lan-sheriff-demo/b -days 3 -devices 6 -endpoints 8

./lan-sheriff serve --data-dir /tmp/lan-sheriff-demo/a --listen 127.0.0.1:2960 --offline --locate=false \
  --open=false --dispatch --dispatch-listen 127.0.0.1:2962
./lan-sheriff serve --data-dir /tmp/lan-sheriff-demo/b --listen 127.0.0.1:2965 --offline --locate=false \
  --open=false --dispatch --dispatch-listen 127.0.0.1:2967
```

Pair them through the dashboard, then capture with headless Chrome on a
debugging port at `deviceScaleFactor: 2`. The stills are downsampled from that
to 1568x774, which is sharper than grabbing them at 1568 directly.

For anything showing traffic arriving, keep a live seed running alongside:

```sh
go run ./scripts/demoseed -out /tmp/lan-sheriff-demo/a -live 300s
```

The seed is fixed, so a re-run produces the same network. Recordings made weeks
apart differ because the interface changed, not because the data did.
