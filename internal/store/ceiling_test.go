package store

import "testing"

// The ceilings exist to stop one request reading the database into memory. They
// were also applied to exports, which is how `lan-sheriff-flows-....csv` came to
// hold 5000 of 152957 connections, and the DNS export 2000 of 48981, in files
// whose names said nothing about it. A number that is not wrong but answers a
// question nobody asked is the hardest kind of bug to notice.
func TestExportIsNotHeldToTheScreenCeiling(t *testing.T) {
	for _, c := range []struct {
		name   string
		filter Filter
		want   int
	}{
		{"a screen asking for too much is capped", Filter{Limit: 999999}, ScreenCeiling},
		{"an export is not", Filter{Limit: 999999, Export: true}, ExportCeiling},
		{"an export still cannot ask for everything", Filter{Limit: 10_000_000, Export: true}, ExportCeiling},
		{"a modest request is honoured either way", Filter{Limit: 42}, 42},
		{"and so is a modest export", Filter{Limit: 42, Export: true}, 42},
		{"no limit still means the default", Filter{}, DefaultLimit},
	} {
		if got := c.filter.limit(); got != c.want {
			t.Errorf("%s: limit() = %d, want %d", c.name, got, c.want)
		}
	}
	if ExportCeiling <= ScreenCeiling {
		t.Fatal("the export ceiling must exceed the screen's, or exports truncate again")
	}
}

// Same rule for the DNS feed, which has its own lower ceiling because it
// refreshes every few seconds.
func TestDNSExportIsNotHeldToTheFeedCeiling(t *testing.T) {
	for _, c := range []struct {
		name string
		opt  DNSOptions
		want int
	}{
		{"the feed is capped", DNSOptions{Limit: 999999}, FeedCeiling},
		{"an export is not", DNSOptions{Limit: 999999, Export: true}, ExportCeiling},
		{"no limit means the feed default", DNSOptions{}, 200},
		{"a modest request is honoured", DNSOptions{Limit: 17}, 17},
	} {
		if got := c.opt.limit(); got != c.want {
			t.Errorf("%s: limit() = %d, want %d", c.name, got, c.want)
		}
	}
	if ExportCeiling <= FeedCeiling {
		t.Fatal("the export ceiling must exceed the feed's, or DNS exports truncate again")
	}
}
