package discover

import "testing"

func TestNormalizeMAC(t *testing.T) {
	// Different sources produce different separators and cases.
	for _, in := range []string{
		"a4:83:e7:11:22:33", "A4-83-E7-11-22-33", "a483e7112233", "A4:83:E7:11:22:33",
	} {
		if got := NormalizeMAC(in); got != "A483E7112233" {
			t.Errorf("NormalizeMAC(%q) = %q", in, got)
		}
	}
	// Normalization filters rather than validates: only hex characters survive.
	// "not a mac" keeps a, a, c. Callers must check the length, which Vendor
	// does, rather than assume a normalized string is a real address.
	if got := NormalizeMAC("not a mac"); got != "AAC" {
		t.Errorf("NormalizeMAC(%q) = %q, want %q", "not a mac", got, "AAC")
	}
	if got := NormalizeMAC(""); got != "" {
		t.Errorf("NormalizeMAC(empty) = %q", got)
	}
}

func TestVendorLookup(t *testing.T) {
	// Apple's registry prefix; a real entry so this exercises the embedded data.
	if v := Vendor("A4:83:E7:11:22:33"); v == "" {
		t.Error("expected a vendor for a registered Apple prefix")
	}
	if v := Vendor(""); v != "" {
		t.Errorf("empty MAC should have no vendor, got %q", v)
	}
	if v := Vendor("zz"); v != "" {
		t.Errorf("garbage should have no vendor, got %q", v)
	}
}

func TestRandomizedMACsHaveNoVendor(t *testing.T) {
	// A randomized address belongs to nobody, so any registry hit would be
	// coincidental and misleading.
	randomized := []string{
		"02:00:00:11:22:33", // bit 1 set
		"06:11:22:33:44:55",
		"0A:11:22:33:44:55",
		"7E:11:22:33:44:55",
	}
	for _, mac := range randomized {
		if !IsRandomized(mac) {
			t.Errorf("IsRandomized(%q) = false, want true", mac)
		}
		if v := Vendor(mac); v != "" {
			t.Errorf("Vendor(%q) = %q, want empty for a randomized address", mac, v)
		}
	}

	assigned := []string{"A4:83:E7:11:22:33", "00:00:00:00:00:01", "3C:22:FB:00:00:01"}
	for _, mac := range assigned {
		if IsRandomized(mac) {
			t.Errorf("IsRandomized(%q) = true, want false", mac)
		}
	}
}

func TestRegistryLoads(t *testing.T) {
	ouiOnce.Do(loadOUI)
	if len(ouiVendors) < 10000 {
		t.Errorf("registry holds %d entries, expected tens of thousands", len(ouiVendors))
	}
}
