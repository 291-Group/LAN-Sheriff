// Command demoseed builds a synthetic LAN Sheriff database for screenshots and
// the README's recordings.
//
// # Why this is a script and not a mode
//
// The obvious design is `lan-sheriff --demo`, and it was rejected. This is a
// security tool: something a person consults to decide whether a device on
// their network is behaving. A build of it that can render fabricated traffic
// as though it were observed is a liability no banner fully retires, the
// screenshot outlives the banner, the support question does not mention it, and
// somebody eventually sees invented findings and believes them.
//
// A repo script has none of that. Nothing here is compiled into the binary, and
// the database it writes has to be pointed at deliberately with --data-dir.
//
// # Why not just screenshot a real network
//
// Because a real one is somebody's home. Hostnames, internal addressing, the
// places they actually connect to and, through the map origin, roughly where
// they live. None of that belongs in a public README, and redacting it after
// the fact is the kind of job that is done correctly four times out of five.
//
// The household below is invented. The organizations are real, because a map of
// plausible destinations is the whole point, but no capture produced any of it.
//
//	go run ./scripts/demoseed -out /tmp/ls-demo
//	./lan-sheriff serve --data-dir /tmp/ls-demo
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/store"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// The seed is fixed so a re-run produces the same picture. Screenshots taken
// weeks apart should differ because the interface changed, not because the
// data did.
const seed = 29112026

// A household with the shape the tool is for: a few things a person chose, and
// a majority they did not think of as computers.
type demoDevice struct {
	name, mac, ip, vendor string
	self                  bool
	services              []string
}

var devices = []demoDevice{
	{name: "Living Room TV", mac: "8C:79:F5:00:00:09", ip: "192.168.4.21", vendor: "Samsung Electronics Co.,Ltd", services: []string{"_airplay._tcp", "_googlecast._tcp"}},
	{name: "Front Door Camera", mac: "44:65:0D:00:00:05", ip: "192.168.4.22", vendor: "Amazon Technologies Inc."},
	{name: "Thermostat", mac: "44:61:32:00:00:04", ip: "192.168.4.23", vendor: "ecobee Inc."},
	{name: "Kitchen Speaker", mac: "5C:AA:FD:00:00:06", ip: "192.168.4.24", vendor: "Sonos, Inc.", services: []string{"_sonos._tcp"}},
	{name: "Work Laptop", mac: "A4:83:E7:00:00:0B", ip: "192.168.4.30", vendor: "Apple, Inc.", self: true},
	{name: "Phone", mac: "F0:18:98:00:00:0E", ip: "192.168.4.31", vendor: "Apple, Inc."},
	{name: "Games Console", mac: "00:D9:D1:00:00:01", ip: "192.168.4.32", vendor: "Sony Interactive Entertainment"},
	{name: "Office Printer", mac: "30:05:5C:00:00:02", ip: "192.168.4.40", vendor: "Brother Industries, Ltd", services: []string{"_ipp._tcp"}},
	{name: "Router", mac: "74:AC:B9:00:00:07", ip: "192.168.4.1", vendor: "Ubiquiti Inc."},
}

// Real organizations at plausible coordinates, so the Watchtower draws arcs
// somewhere a reader recognises rather than into empty ocean.
type demoDest struct {
	ip, org, country, countryName, city string
	lat, lon                            float64
	asn                                 int
}

var dests = []demoDest{
	{"45.57.40.11", "Netflix Streaming Services", "US", "United States", "Los Gatos", 37.2358, -121.9624, 2906},
	{"142.250.80.46", "Google LLC", "US", "United States", "Mountain View", 37.4056, -122.0775, 15169},
	{"104.16.132.229", "Cloudflare, Inc.", "US", "United States", "San Francisco", 37.7749, -122.4194, 13335},
	{"52.94.236.248", "Amazon.com, Inc.", "US", "United States", "Ashburn", 39.0438, -77.4874, 16509},
	{"23.55.214.9", "Akamai Technologies, Inc.", "US", "United States", "Cambridge", 42.3736, -71.1097, 20940},
	{"13.107.42.14", "Microsoft Corporation", "US", "United States", "Redmond", 47.6740, -122.1215, 8075},
	{"17.253.144.10", "Apple Inc.", "US", "United States", "Cupertino", 37.3230, -122.0322, 714},
	{"3.33.152.147", "Amazon.com, Inc.", "IE", "Ireland", "Dublin", 53.3498, -6.2603, 16509},
	{"210.89.164.90", "Samsung Electronics Co.,Ltd", "KR", "South Korea", "Seoul", 37.5665, 126.9780, 4766},
	{"185.60.216.35", "Meta Platforms, Inc.", "SE", "Sweden", "Luleå", 65.5848, 22.1567, 32934},
	{"91.108.56.170", "Telegram Messenger Inc", "NL", "Netherlands", "Amsterdam", 52.3676, 4.9041, 62041},
	{"103.224.182.251", "Trellian Pty Ltd", "AU", "Australia", "Melbourne", -37.8136, 144.9631, 133618},
}

// Growing the invented network, for the arm64 performance pass.
//
// The curated household above is nine devices and twelve destinations, which is
// what the recordings and the README stills use and what the fixed seed makes
// reproducible. It is deliberately the size of a real home, and that is exactly
// why it cannot answer "does the map still draw at three hundred endpoints".
//
// So the household is never modified. These append to it, and with the default
// flags nothing is appended at all, so the network every existing recording was
// made against is unchanged. Not byte for byte, because the timestamps are
// relative to the run, but the same devices, the same destinations and the same
// findings.
//
// # Why the addresses are from the documentation ranges
//
// 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 are reserved by RFC 5737 for
// exactly this and are guaranteed to belong to nobody. A performance test needs
// three hundred plausible-looking addresses, and inventing them by picking
// numbers would mean putting somebody's real address, and a fabricated
// organization name next to it, into a database and onto a map. The coordinates
// and organizations here are written directly rather than looked up, so no
// enrichment happens and nothing is claimed about anyone.
var syntheticPlaces = []struct {
	country, countryName, city string
	lat, lon                   float64
}{
	{"US", "United States", "Chicago", 41.8781, -87.6298},
	{"GB", "United Kingdom", "London", 51.5072, -0.1276},
	{"DE", "Germany", "Frankfurt", 50.1109, 8.6821},
	{"JP", "Japan", "Tokyo", 35.6762, 139.6503},
	{"BR", "Brazil", "Sao Paulo", -23.5558, -46.6396},
	{"SG", "Singapore", "Singapore", 1.3521, 103.8198},
	{"ZA", "South Africa", "Cape Town", -33.9249, 18.4241},
	{"CA", "Canada", "Toronto", 43.6532, -79.3832},
	{"IN", "India", "Mumbai", 19.0760, 72.8777},
	{"AU", "Australia", "Sydney", -33.8688, 151.2093},
}

// docRanges are the RFC 5737 documentation prefixes, in the order they are used.
var docRanges = []string{"192.0.2.", "198.51.100.", "203.0.113."}

// growTo appends generated devices and destinations until each list reaches the
// requested size. A target at or below the curated size changes nothing.
func growTo(wantDevices, wantDests int) {
	// Both base lengths are taken **before** either loop appends. Reading
	// len(dests) inside the loop instead meant it grew with every iteration, so
	// the offset was always zero, every generated entry got the same address,
	// and three hundred of them collapsed into one row on insert. The seeder
	// reported success and produced thirteen endpoints.
	baseDests := len(dests)
	baseDevices := len(devices)

	for i := baseDests; i < wantDests; i++ {
		n := i - baseDests // 0-based index into the generated run
		p := syntheticPlaces[n%len(syntheticPlaces)]
		block := docRanges[(n/254)%len(docRanges)]
		dests = append(dests, demoDest{
			ip:          fmt.Sprintf("%s%d", block, (n%254)+1),
			org:         fmt.Sprintf("Example Networks %03d", n+1),
			country:     p.country,
			countryName: p.countryName,
			city:        p.city,
			// Nudged apart so three hundred arcs do not land on ten exact
			// points, which would make the map look correct while hiding
			// whatever it does with genuinely distinct coordinates.
			lat: p.lat + float64(n%17)*0.35 - 2.8,
			lon: p.lon + float64(n%23)*0.45 - 5.0,
			asn: 64500 + n, // the private-use ASN range, for the same reason
		})
	}

	for i := baseDevices; i < wantDevices; i++ {
		n := i - baseDevices
		name := fmt.Sprintf("Device %03d", n+1)
		devices = append(devices, demoDevice{
			name:   name,
			mac:    fmt.Sprintf("02:00:5E:%02X:%02X:%02X", n>>16&0xff, n>>8&0xff, n&0xff),
			ip:     fmt.Sprintf("192.168.4.%d", 100+n%150),
			vendor: "Locally Administered",
		})

		// **Give it somewhere to talk to, or none of this counts.**
		//
		// A generated device with no habits produces no flows, and a generated
		// destination nothing reaches never appears on the map: the Watchtower
		// draws from flows joined to endpoints, not from the endpoints table.
		// Stopping at the two lists above would make a seed asking for 320
		// endpoints produce 320 rows and a map still showing the original twelve
		// arcs: real measurements of the wrong thing.
		for k := 0; k < habitsPerDevice; k++ {
			if len(dests) == baseDests {
				break // nothing generated to talk to
			}
			// Spread across the generated destinations rather than the curated
			// ones, so growing the network grows the map.
			d := baseDests + (n*habitsPerDevice+k)%(len(dests)-baseDests)
			habits[name] = append(habits[name], demoHabit{
				dst:     dests[d].ip,
				port:    443,
				proto:   types.ProtoTCP,
				perHour: 1 + (n+k)%4,
				app:     "",
			})
		}
	}
}

// habitsPerDevice is how many destinations each generated device reaches.
//
// Four, because the point is a map with many distinct arcs rather than many
// connections along a few: 300 endpoints reached by 60 devices needs each
// device to have several, and one apiece would leave three quarters of the
// generated destinations unreferenced.
const habitsPerDevice = 4

func main() {
	out := flag.String("out", "", "directory to write the demo database into (required)")
	days := flag.Int("days", 5, "how much history to fabricate")
	live := flag.Duration("live", 0, "after seeding, keep adding traffic for this long, for recording the map filling up")
	nDevices := flag.Int("devices", len(devices), "grow the invented network to this many devices (for performance testing)")
	nDests := flag.Int("endpoints", len(dests), "grow the invented network to this many external endpoints")
	flag.Parse()
	growTo(*nDevices, *nDests)
	if *out == "" {
		log.Fatal("demoseed: -out is required")
	}
	if *live > 0 {
		// Recording only. The database is already seeded and an instance is
		// already serving it; this just keeps arriving.
		if err := drip(*out, *live); err != nil {
			log.Fatalf("demoseed: %v", err)
		}
		return
	}
	if err := run(*out, *days); err != nil {
		log.Fatalf("demoseed: %v", err)
	}
}

// drip appends traffic in real time, so the Watchtower can be filmed filling up.
//
// The map's headline asset is arcs arriving, and a seeded database is
// motionless, every flow in it is already hours old by the time anything
// renders. Rather than fake the animation in the client, the traffic genuinely
// arrives: this writes into the same database the dashboard is reading, and the
// dashboard notices on its next poll exactly as it would with a live capture.
//
// Safe alongside a running instance because the store is WAL with a busy
// timeout, which is the arrangement that makes a reader and a writer coexist.
func drip(dir string, d time.Duration) error {
	st, err := store.Open(filepath.Join(dir, "sheriff.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	ids := map[string]string{}
	for _, d := range devices {
		var id string
		if err := st.DB().QueryRowContext(ctx,
			`SELECT device_id FROM device_addresses WHERE ip = ?`, d.ip).Scan(&id); err == nil {
			ids[d.name] = id
		}
	}
	if len(ids) == 0 {
		return fmt.Errorf("no seeded devices found in %s, run without -live first", dir)
	}

	deadline := time.Now().Add(d)
	n := 0
	for time.Now().Before(deadline) {
		var batch []types.Flow
		for name, hs := range habits {
			id, ok := ids[name]
			if !ok || len(hs) == 0 || rng.Intn(3) != 0 {
				continue
			}
			h := hs[rng.Intn(len(hs))]
			now := time.Now()
			batch = append(batch, types.Flow{
				DeviceID: id, Process: h.app,
				SrcIP: ipFor(name), SrcPort: uint16(30000 + rng.Intn(30000)),
				DstIP: h.dst, DstPort: h.port, Proto: h.proto,
				TSStart: now, TSLast: now, Active: true,
				BytesOut:  uint64(600 + rng.Intn(9000)),
				BytesIn:   uint64(1200 + rng.Intn(400000)),
				Direction: types.DirOut, Established: true,
			})
		}
		if len(batch) > 0 {
			if err := st.WriteFlows(ctx, batch); err != nil {
				return err
			}
			// **A real capture touches the endpoint as well as the flow.**
			//
			// Leaving this out made the header disagree with the panel beneath
			// it: the summary counts destinations by the endpoint's own
			// last_seen and read zero, while the egress view derived twelve from
			// the flows. Nothing was wrong with either query. The traffic simply
			// arrived in a shape no capture produces, and the disagreement was
			// an artifact of this script rather than a defect in the product,
			// which is worth stating because it looked exactly like a bug.
			seen := make(map[string]store.EndpointSighting, len(batch))
			for _, f := range batch {
				seen[f.DstIP] = store.EndpointSighting{Seen: f.TSLast}
			}
			if err := st.TouchEndpoints(ctx, seen); err != nil {
				return err
			}
			n += len(batch)
		}
		time.Sleep(700 * time.Millisecond)
	}
	fmt.Printf("added %d live connections over %s\n", n, d)
	return nil
}

func run(dir string, days int) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// A stale database would be merged with, not replaced, and the result would
	// be neither the old picture nor the new one.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(filepath.Join(dir, "sheriff.db"+suffix))
	}

	st, err := store.Open(filepath.Join(dir, "sheriff.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	rng := rand.New(rand.NewSource(seed))
	now := time.Now().Truncate(time.Hour)
	start := now.AddDate(0, 0, -days)

	ids, err := seedDevices(ctx, st, start)
	if err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	if err := seedEndpoints(ctx, st, start, now); err != nil {
		return fmt.Errorf("endpoints: %w", err)
	}
	n, err := seedFlows(ctx, st, ids, rng, start, now)
	if err != nil {
		return fmt.Errorf("flows: %w", err)
	}
	q, err := seedDNS(ctx, st, ids, rng, start, now)
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}

	// **The install has to look as old as the traffic in it.**
	//
	// Every rule that reasons about what is normal asks how much history exists,
	// and the answer comes from a setting written when the database is first
	// opened, which, for a database created by this script, is a moment ago. So
	// five days of fabricated traffic sat behind a baseline of zero and every
	// rule stayed silent, leaving the Wanted List empty in the one screenshot
	// that most needs it.
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES ('roster_baseline_at', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		fmt.Sprint(start.Unix())); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}

	// The household's own position, so the Watchtower draws arcs from a place
	// rather than from the neutral point it falls back to. Invented like the
	// rest of it, nothing here reveals where the machine running this is.
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES ('map_origin', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		`{"lat":43.6532,"lon":-79.3832,"label":"Toronto","country":"CA","city":"Toronto","known":true}`,
	); err != nil {
		return fmt.Errorf("origin: %w", err)
	}

	fmt.Printf("demo database ready in %s\n", dir)
	fmt.Printf("  %d devices, %d flows, %d DNS lookups, %d days of history\n",
		len(ids), n, q, days)
	fmt.Printf("\nrun it with:\n  ./lan-sheriff serve --data-dir %s --locate=false\n", dir)
	fmt.Printf("\nthe suspicion rules fill the Wanted List on their own, within a pass or two.\n")
	return nil
}

// seedDevices puts the household on the Roster and returns name -> device id.
func seedDevices(ctx context.Context, st *store.Store, at time.Time) (map[string]string, error) {
	ids := map[string]string{}
	for _, d := range devices {
		id, err := st.ObserveDevice(ctx, types.Sighting{
			MAC: d.mac, IP: d.ip, Name: d.name, Vendor: d.vendor,
			Services: d.services, IsSelf: d.self, Source: "neighbour", SeenAt: at,
		})
		if err != nil {
			return nil, err
		}
		// Seen again just now, so the Roster shows them online rather than as a
		// list of things that have all been away for five days.
		if _, err := st.ObserveDevice(ctx, types.Sighting{
			MAC: d.mac, IP: d.ip, Source: "neighbour", SeenAt: time.Now(),
		}); err != nil {
			return nil, err
		}
		ids[d.name] = id
	}
	return ids, nil
}

// seedEndpoints writes the destinations with the enrichment the map needs.
//
// Written directly rather than left to the enricher: the enricher would want a
// network, a GeoIP database and time, and the point of this script is a picture
// that exists a second after it runs.
func seedEndpoints(ctx context.Context, st *store.Store, first, last time.Time) error {
	for _, e := range dests {
		if _, err := st.DB().ExecContext(ctx, `
INSERT INTO endpoints (ip, org, asn, country, country_name, city, lat, lon,
                       is_internal, first_seen, last_seen, enriched_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen`,
			e.ip, e.org, e.asn, e.country, e.countryName, e.city, e.lat, e.lon,
			first.Unix(), last.Unix(), last.Unix()); err != nil {
			return err
		}
	}
	// The household's own addresses, so internal traffic is classified as such
	// rather than drawn as connections to the sea.
	for _, d := range devices {
		if _, err := st.DB().ExecContext(ctx, `
INSERT INTO endpoints (ip, is_internal, first_seen, last_seen)
VALUES (?, 1, ?, ?) ON CONFLICT(ip) DO NOTHING`,
			d.ip, first.Unix(), last.Unix()); err != nil {
			return err
		}
	}
	return nil
}

// what each device talks to, and how much. The shares are what make the
// Wanted List's rules produce anything: a television with a metronomic habit
// looks different from a laptop, and only because the traffic says so.
type demoHabit struct {
	dst     string
	port    uint16
	proto   types.Proto
	perHour int
	app     string
	// everySec makes this a beacon rather than ordinary traffic: a connection
	// on a fixed cadence instead of whenever somebody happens to use the thing.
	//
	// The distinction is the entire basis of the rule. A television checking in
	// six times an hour at random moments is just traffic. A rhythm is what
	// nobody chose: the same interval, all night, whether or not anyone is home.
	everySec int
}

var habits = map[string][]demoHabit{
	"Living Room TV": {
		{"45.57.40.11", 443, types.ProtoTCP, 14, "", 0},
		// The reason this device is interesting, and the finding the Wanted List
		// screenshot is for: a check-in to the manufacturer every ten minutes,
		// all night, whether or not anybody is watching.
		{"210.89.164.90", 443, types.ProtoTCP, 0, "", 600},
		{"142.250.80.46", 443, types.ProtoTCP, 4, "", 0},
	},
	"Front Door Camera": {
		{"52.94.236.248", 443, types.ProtoTCP, 22, "", 0},
		{"3.33.152.147", 443, types.ProtoTCP, 3, "", 0},
	},
	"Thermostat": {{"52.94.236.248", 443, types.ProtoTCP, 2, "", 0}},
	"Kitchen Speaker": {
		{"23.55.214.9", 443, types.ProtoTCP, 5, "", 0},
		{"17.253.144.10", 443, types.ProtoTCP, 2, "", 0},
	},
	"Work Laptop": {
		{"142.250.80.46", 443, types.ProtoTCP, 40, "Google Chrome", 0},
		{"104.16.132.229", 443, types.ProtoTCP, 26, "Google Chrome", 0},
		{"13.107.42.14", 443, types.ProtoTCP, 12, "Slack", 0},
		{"185.60.216.35", 443, types.ProtoTCP, 9, "Google Chrome", 0},
		{"17.253.144.10", 443, types.ProtoTCP, 6, "syncthing", 0},
		// One connection somewhere this network essentially never goes.
		{"103.224.182.251", 443, types.ProtoTCP, 0, "Google Chrome", 0},
	},
	"Phone": {
		{"17.253.144.10", 443, types.ProtoTCP, 18, "", 0},
		{"91.108.56.170", 443, types.ProtoTCP, 7, "", 0},
		{"142.250.80.46", 443, types.ProtoTCP, 11, "", 0},
	},
	"Games Console": {{"13.107.42.14", 443, types.ProtoTCP, 8, "", 0}},
	// Plain HTTP to the manufacturer, which is the sort of thing a printer does
	// and nobody ever finds out about.
	"Office Printer": {{"23.55.214.9", 80, types.ProtoTCP, 2, "", 0}},
}

func seedFlows(
	ctx context.Context, st *store.Store, ids map[string]string,
	rng *rand.Rand, start, now time.Time,
) (int, error) {
	var batch []types.Flow
	total := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := st.WriteFlows(ctx, batch); err != nil {
			return err
		}
		total += len(batch)
		batch = batch[:0]
		return nil
	}

	for at := start; at.Before(now); at = at.Add(time.Hour) {
		// People sleep, and a baseline that does not know that reports every
		// morning as an anomaly.
		busy := 1.0
		switch h := at.Hour(); {
		case h >= 1 && h < 7:
			busy = 0.15
		case h >= 19 && h < 23:
			busy = 1.6
		}

		for name, hs := range habits {
			id, ok := ids[name]
			if !ok {
				continue
			}
			src := ipFor(name)
			for _, h := range hs {
				if h.everySec > 0 {
					// A cadence, not a count. Small jitter so it is a plausible
					// device rather than a metronome, the rule wants regularity
					// above 0.85, and real beacons sit comfortably there.
					for off := 0; off < 3600; off += h.everySec {
						ts := at.Add(time.Duration(off+rng.Intn(21)-10) * time.Second)
						batch = append(batch, types.Flow{
							DeviceID: id, SrcIP: src,
							SrcPort: uint16(30000 + rng.Intn(30000)),
							DstIP:   h.dst, DstPort: h.port, Proto: h.proto,
							TSStart: ts, TSLast: ts.Add(2 * time.Second),
							BytesOut:  uint64(400 + rng.Intn(300)),
							BytesIn:   uint64(500 + rng.Intn(900)),
							Direction: types.DirOut, Established: true,
						})
					}
					continue
				}
				n := h.perHour
				if n > 1 {
					n = int(float64(n) * busy)
					if jitter := rng.Intn(5) - 2; n+jitter > 0 {
						n += jitter
					}
				}
				for i := 0; i < n; i++ {
					ts := at.Add(time.Duration(rng.Intn(3600)) * time.Second)
					batch = append(batch, types.Flow{
						DeviceID: id, Process: h.app,
						SrcIP: src, SrcPort: uint16(30000 + rng.Intn(30000)),
						DstIP: h.dst, DstPort: h.port, Proto: h.proto,
						TSStart: ts, TSLast: ts.Add(time.Duration(rng.Intn(90)) * time.Second),
						BytesOut:  uint64(600 + rng.Intn(9000)),
						BytesIn:   uint64(1200 + rng.Intn(400000)),
						Direction: types.DirOut, Established: true,
					})
				}
			}
		}
		if len(batch) > 4000 {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}

	// The single rare destination, placed inside the window the rules examine so
	// it is on the Wanted List when the screenshot is taken rather than an hour
	// later.
	batch = append(batch, types.Flow{
		DeviceID: ids["Work Laptop"], Process: "Google Chrome",
		SrcIP: ipFor("Work Laptop"), SrcPort: 51244,
		DstIP: "103.224.182.251", DstPort: 443, Proto: types.ProtoTCP,
		TSStart: now.Add(-25 * time.Minute), TSLast: now.Add(-24 * time.Minute),
		BytesOut: 3100, BytesIn: 8800, Direction: types.DirOut, Established: true,
	})
	return total, flush()
}

func ipFor(name string) string {
	for _, d := range devices {
		if d.name == name {
			return d.ip
		}
	}
	return ""
}

// The domains behind the traffic, so Radio Chatter has something to say.
var lookups = map[string][]string{
	"Living Room TV":    {"api.samsungcloud.tv", "occ.samsungqbe.com", "nflxvideo.net", "cdn.netflix.com"},
	"Front Door Camera": {"device-api.ring.com", "s3.amazonaws.com"},
	"Thermostat":        {"api.ecobee.com"},
	"Kitchen Speaker":   {"sonos-fw.akamaized.net", "ws.sonos.com"},
	"Work Laptop":       {"www.google.com", "github.com", "slack.com", "cdn.jsdelivr.net", "registry.npmjs.org"},
	"Phone":             {"gateway.icloud.com", "api.telegram.org", "www.googleapis.com"},
	"Games Console":     {"xbox.com", "playstation.net"},
	"Office Printer":    {"brother-update.akamaized.net"},
}

func seedDNS(
	ctx context.Context, st *store.Store, ids map[string]string,
	rng *rand.Rand, start, now time.Time,
) (int, error) {
	n := 0
	for at := start; at.Before(now); at = at.Add(20 * time.Minute) {
		for name, qs := range lookups {
			id, ok := ids[name]
			if !ok || rng.Intn(3) != 0 {
				continue
			}
			q := qs[rng.Intn(len(qs))]
			ts := at.Add(time.Duration(rng.Intn(1200)) * time.Second)
			if _, err := st.DB().ExecContext(ctx, `
INSERT INTO dns_events (ts, device_id, qname, qtype, resp_ms)
VALUES (?, ?, ?, 'A', ?)`, ts.Unix(), id, q, 8+rng.Intn(60)); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}
