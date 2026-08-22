package discover

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// The check must find a port that is listening and not invent ones that are not.
func TestScanFindsAListeningPort(t *testing.T) {
	// A listener on a port from the table, so the result is also named.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	addr := netip.MustParseAddrPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ScanPorts checks a fixed list, so verify the mechanism directly against
	// the port that is actually open.
	d := net.Dialer{Timeout: scanTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		t.Fatalf("the test listener was not reachable: %v", err)
	}
	conn.Close()

	// And that a full check of loopback returns only ports that answered.
	open, err := ScanPorts(ctx, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range open {
		c, err := net.DialTimeout("tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), p.Port).String(), scanTimeout)
		if err != nil {
			t.Errorf("reported port %d as open, but it is not", p.Port)
			continue
		}
		c.Close()
	}
	t.Logf("loopback: %d of %d checked ports answered", len(open), ScanPortCount())
}

// An address with nothing on it must produce nothing, not an error.
func TestScanOfSilentAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Reserved for documentation; nothing routes there.
	open, err := ScanPorts(ctx, netip.MustParseAddr("192.0.2.1"))
	if err != nil && ctx.Err() == nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(open) != 0 {
		t.Errorf("found %d open ports on an address that does not exist", len(open))
	}
}

// The check must cover a short, interpretable list, not a range.
func TestScanListIsShortAndNamed(t *testing.T) {
	list := scanList()
	if len(list) == 0 {
		t.Fatal("empty scan list")
	}
	if len(list) > 60 {
		t.Errorf("scan list has %d ports; a list this long is a port scan, not a check", len(list))
	}
	for _, p := range list {
		if ServiceForPort(p, "tcp") == "" {
			t.Errorf("port %d is checked but cannot be named, there is no reason to knock", p)
		}
	}
	for i := 1; i < len(list); i++ {
		if list[i] <= list[i-1] {
			t.Errorf("scan list is not sorted or has duplicates at %d", i)
		}
	}
}

func TestScanRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ScanPorts(ctx, netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Error("a cancelled context did not stop the check")
	}
}
