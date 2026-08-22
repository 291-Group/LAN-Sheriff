package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func dnsEvent(qname string, at time.Time, device, flagged string) types.DNSEvent {
	return types.DNSEvent{
		TS: at, DeviceID: device, QName: qname, QType: "A",
		Answers: []string{"93.184.216.34"}, Flagged: flagged,
	}
}

func TestDNSEventsRoundTripAndFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	err := s.WriteDNS(ctx, []types.DNSEvent{
		dnsEvent("telemetry.example.com", now, "lan-192.168.1.10", "telemetry"),
		dnsEvent("plain.example.org", now.Add(-time.Minute), "lan-192.168.1.11", ""),
		dnsEvent("old.example.net", now.Add(-48*time.Hour), "lan-192.168.1.10", ""),
	})
	if err != nil {
		t.Fatalf("WriteDNS: %v", err)
	}

	all, err := s.DNSEvents(ctx, DNSOptions{Since: now.Add(-2 * time.Hour)})
	if err != nil {
		t.Fatalf("DNSEvents: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d events in a 2h window, want 2", len(all))
	}
	// Newest first, so the feed reads top-down.
	if all[0].QName != "telemetry.example.com" {
		t.Errorf("first event = %q, want the newest", all[0].QName)
	}
	// Answers survive the JSON round trip.
	if len(all[0].Answers) != 1 || all[0].Answers[0] != "93.184.216.34" {
		t.Errorf("answers = %v", all[0].Answers)
	}

	cases := []struct {
		name string
		opt  DNSOptions
		want int
	}{
		{"flagged only", DNSOptions{Since: now.Add(-2 * time.Hour), FlaggedOnly: true}, 1},
		{"by device", DNSOptions{Since: now.Add(-2 * time.Hour), Device: "lan-192.168.1.11"}, 1},
		{"by domain substring", DNSOptions{Since: now.Add(-2 * time.Hour), Domain: "example.com"}, 1},
		{"wide window", DNSOptions{Since: now.Add(-72 * time.Hour)}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := s.DNSEvents(ctx, c.opt)
			if err != nil {
				t.Fatalf("DNSEvents: %v", err)
			}
			if len(got) != c.want {
				t.Errorf("got %d events, want %d", len(got), c.want)
			}
		})
	}
}

// The "new" flag is the subtle part: it must be computed against all of history,
// not the window being viewed, or every domain looks new whenever you narrow the
// range.
func TestTopDomainsMarksNewAgainstAllHistoryNotTheWindow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	s.WriteDNS(ctx, []types.DNSEvent{
		// A long-standing domain, first seen two days ago and again just now.
		dnsEvent("cdn.example.com", now.Add(-48*time.Hour), "d1", ""),
		dnsEvent("cdn.example.com", now.Add(-time.Minute), "d1", ""),
		dnsEvent("cdn.example.com", now, "d2", ""),
		// A genuinely new one, first seen inside the window.
		dnsEvent("brandnew.example.net", now.Add(-30*time.Second), "d1", ""),
	})

	got, err := s.TopDomains(ctx, now.Add(-time.Hour), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatalf("TopDomains: %v", err)
	}

	byDomain := map[string]DomainSummary{}
	for _, d := range got {
		byDomain[d.Domain] = d
	}

	cdn, ok := byDomain["cdn.example.com"]
	if !ok {
		t.Fatal("the busy domain should appear in the window")
	}
	if cdn.New {
		t.Error("a domain first seen two days ago is not new, even in a one-hour window")
	}
	if cdn.Lookups != 2 {
		t.Errorf("lookups = %d, want the 2 inside the window", cdn.Lookups)
	}
	if cdn.Devices != 2 {
		t.Errorf("devices = %d, want 2 distinct askers", cdn.Devices)
	}

	fresh, ok := byDomain["brandnew.example.net"]
	if !ok {
		t.Fatal("the new domain should appear")
	}
	if !fresh.New {
		t.Error("a domain first seen inside the window is new")
	}
}

func TestNewDomainsOnlyReturnsFirstSightings(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	s.WriteDNS(ctx, []types.DNSEvent{
		dnsEvent("established.example.com", now.Add(-72*time.Hour), "d1", ""),
		dnsEvent("established.example.com", now, "d1", ""),
		dnsEvent("fresh.example.net", now.Add(-time.Minute), "d1", ""),
	})

	got, err := s.NewDomains(ctx, now.Add(-time.Hour), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatalf("NewDomains: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d new domains, want 1: %+v", len(got), got)
	}
	if got[0].Domain != "fresh.example.net" {
		t.Errorf("new domain = %q, want the one first seen in the window", got[0].Domain)
	}
	if !got[0].New {
		t.Error("everything from NewDomains is by definition new")
	}
}

func TestDNSSummaryCounts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	s.WriteDNS(ctx, []types.DNSEvent{
		dnsEvent("a.example.com", now.Add(-72*time.Hour), "d1", ""), // outside the window
		dnsEvent("a.example.com", now, "d1", ""),
		dnsEvent("b.example.com", now, "d2", "ads"),
		dnsEvent("c.example.com", now, "d2", "malware"),
	})

	st, err := s.DNSSummary(ctx, now.Add(-time.Hour), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("DNSSummary: %v", err)
	}
	if st.Lookups != 3 {
		t.Errorf("lookups = %d, want 3 inside the window", st.Lookups)
	}
	if st.Domains != 3 {
		t.Errorf("domains = %d, want 3", st.Domains)
	}
	// a.example.com was first seen outside the window, so only b and c are new.
	if st.NewDomains != 2 {
		t.Errorf("new domains = %d, want 2", st.NewDomains)
	}
	if st.Flagged != 2 {
		t.Errorf("flagged = %d, want 2", st.Flagged)
	}
	if st.Devices != 2 {
		t.Errorf("devices = %d, want 2", st.Devices)
	}
}

// Labelling is applied after the fact so that adding a list re-labels history,
// rather than only affecting lookups that arrive later.
func TestLabelDNSAppliesToSubdomainsAndHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	s.WriteDNS(ctx, []types.DNSEvent{
		dnsEvent("doubleclick.net", now, "d1", ""),
		dnsEvent("stats.g.doubleclick.net", now, "d1", ""),
		dnsEvent("notdoubleclick.net", now, "d1", ""),
		dnsEvent("already.example.com", now, "d1", "malware"),
	})

	n, err := s.LabelDNS(ctx, "doubleclick.net", "ads")
	if err != nil {
		t.Fatalf("LabelDNS: %v", err)
	}
	if n != 2 {
		t.Errorf("labelled %d rows, want the domain and its subdomain", n)
	}

	events, _ := s.DNSEvents(ctx, DNSOptions{Since: now.Add(-time.Hour), Limit: 100})
	got := map[string]string{}
	for _, e := range events {
		got[e.QName] = e.Flagged
	}
	if got["doubleclick.net"] != "ads" || got["stats.g.doubleclick.net"] != "ads" {
		t.Errorf("expected both to be labelled ads, got %v", got)
	}
	// A name that merely ends with the same text must not be caught.
	if got["notdoubleclick.net"] != "" {
		t.Errorf("notdoubleclick.net was labelled %q; suffix matching must respect label boundaries", got["notdoubleclick.net"])
	}
	// An existing label is not overwritten by a later, less severe one.
	if got["already.example.com"] != "malware" {
		t.Errorf("an existing label should not be replaced, got %q", got["already.example.com"])
	}
}
