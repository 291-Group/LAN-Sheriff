package enrich

import (
	"io/fs"
	"log/slog"
	"net/netip"
	"sync"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// geoDB wraps the three MaxMind-format databases we may have available. Each is
// optional and each can appear at any time: the datasets are fetched in the
// background, so lookups have to cope with a database that is missing now and
// present in a minute.
type geoDB struct {
	mgr *Manager

	mu      sync.RWMutex
	country *maxminddb.Reader
	asn     *maxminddb.Reader
	city    *maxminddb.Reader
}

func newGeoDB(mgr *Manager) *geoDB {
	g := &geoDB{mgr: mgr}
	_ = g.Reload()
	return g
}

// Reload picks up datasets that have appeared since the last attempt, and
// reports whether any of them are newly available.
func (g *geoDB) Reload() bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	opened := false
	open := func(name string, cur **maxminddb.Reader) {
		if *cur != nil {
			return
		}
		path, err := g.mgr.Open(name)
		if err != nil {
			if err != fs.ErrNotExist {
				slog.Debug("dataset unavailable", "name", name, "err", err)
			}
			return
		}
		r, err := maxminddb.Open(path)
		if err != nil {
			slog.Warn("could not read dataset", "name", name, "err", err)
			return
		}
		*cur = r
		opened = true
	}

	open(fileCountry, &g.country)
	open(fileASN, &g.asn)
	open(fileCity, &g.city)
	return opened
}

// Ready reports whether any location lookup is possible at all.
func (g *geoDB) Ready() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.country != nil || g.city != nil
}

// Complete reports whether every dataset we expect to have is loaded. Enrichment
// results are only worth persisting once this holds, because an endpoint
// resolved against a half-loaded set would be stamped "enriched" while missing
// the organization or the location it should have had.
func (g *geoDB) Complete() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return (g.country != nil || g.city != nil) && g.asn != nil
}

func (g *geoDB) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range []**maxminddb.Reader{&g.country, &g.asn, &g.city} {
		if *r != nil {
			(*r).Close()
			*r = nil
		}
	}
}

type geoResult struct {
	Country     string
	CountryName string
	City        string
	Lat, Lon    float64
	ASN         int
	Org         string
}

// countryRecord is the shape of both the country and the city databases, as far
// as the country fields go.
type countryRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

type cityRecord struct {
	countryRecord
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type asnRecord struct {
	Number int    `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// Lookup resolves everything we can about an address from the local databases.
//
// City precision is used when available; otherwise the country's approximate
// centre stands in, so an endpoint always has somewhere to be drawn as soon as
// its country is known.
func (g *geoDB) Lookup(addr netip.Addr) geoResult {
	g.mu.RLock()
	country, asn, city := g.country, g.asn, g.city
	g.mu.RUnlock()

	var out geoResult

	if city != nil {
		var rec cityRecord
		if res := city.Lookup(addr); res.Found() {
			if err := res.Decode(&rec); err == nil {
				out.Country = rec.Country.ISOCode
				out.CountryName = rec.Country.Names["en"]
				out.City = rec.City.Names["en"]
				out.Lat, out.Lon = rec.Location.Latitude, rec.Location.Longitude
			}
		}
	}

	if out.Country == "" && country != nil {
		var rec countryRecord
		if res := country.Lookup(addr); res.Found() {
			if err := res.Decode(&rec); err == nil {
				out.Country = rec.Country.ISOCode
				out.CountryName = rec.Country.Names["en"]
			}
		}
	}

	if out.Lat == 0 && out.Lon == 0 && out.Country != "" {
		if lat, lon, ok := countryCentroid(out.Country); ok {
			out.Lat, out.Lon = lat, lon
		}
	}

	if asn != nil {
		var rec asnRecord
		if res := asn.Lookup(addr); res.Found() {
			if err := res.Decode(&rec); err == nil {
				out.ASN, out.Org = rec.Number, rec.Org
			}
		}
	}

	return out
}
