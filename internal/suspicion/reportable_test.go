package suspicion

import "testing"

// The endpoints table cannot be the authority on this: its flag is unset until
// enrichment reaches an address, so a destination with no row reads as external.
// That put 127.0.0.1 at the top of the beaconing candidates on a real database.
func TestIsReportable(t *testing.T) {
	unreportable := []string{
		"127.0.0.1", "::1", // a machine talking to itself
		"192.168.1.10", "10.0.0.5", "172.16.3.9", // this network
		"169.254.10.1", "fe80::1", // link-local
		"224.0.0.251", "ff02::fb", // multicast groups
		"100.64.0.1", "100.127.255.254", // carrier-grade NAT
		"0.0.0.0", "::",
		"not-an-address", "",
	}
	for _, a := range unreportable {
		if IsReportable(a) {
			t.Errorf("IsReportable(%q) = true, want false", a)
		}
	}

	reportable := []string{
		"93.184.216.34", "1.1.1.1", "8.8.8.8",
		"2606:4700::1111", "160.79.104.10",
		"100.63.255.255", "100.128.0.1", // just outside the CGNAT range
	}
	for _, a := range reportable {
		if !IsReportable(a) {
			t.Errorf("IsReportable(%q) = false, want true", a)
		}
	}
}
