package discover

import (
	"testing"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// The cases below are the devices actually on the development network, which is
// the only honest way to check that the rules fire on real evidence rather than
// on evidence invented to match them.
func TestInferTypeOnRealDevices(t *testing.T) {
	cases := []struct {
		name     string
		device   types.Device
		services []string
		gateway  bool
		want     string
		because  string
	}{
		{
			name:     "Samsung printer, by its advertised services",
			device:   types.Device{Vendor: "Samsung Electronics Co.,Ltd", Model: "Samsung M2020 Series"},
			services: []string{"_printer._tcp", "_ipp._tcp", "_http._tcp"},
			// The model string "Samsung M2020 Series" names no category, so the
			// advertised services are what identify it.
			want: TypePrinter, because: ByService,
		},
		{
			name:    "TP-Link router, because it is the default route",
			device:  types.Device{Vendor: "TP-Link Systems Inc."},
			gateway: true,
			want:    TypeRouter, because: ByGateway,
		},
		{
			name:   "Raspberry Pi, by vendor alone",
			device: types.Device{Vendor: "Raspberry Pi Trading Ltd"},
			want:   TypeSBC, because: ByVendor,
		},
		{
			name:     "this machine wins over everything else",
			device:   types.Device{IsSelf: true, Vendor: "Apple, Inc.", Hostname: "workshop-mac.local"},
			services: []string{"_airplay._tcp", "_smb._tcp"},
			want:     TypeThisMachine, because: BySelf,
		},
		{
			name:     "Apple device advertising DLNA is not classified as Apple-anything",
			device:   types.Device{Vendor: "Apple, Inc."},
			services: []string{"MediaServer", "ContentDirectory"},
			want:     TypeUnknown,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := InferType(c.device, c.services, c.gateway)
			if got.Type != c.want {
				t.Errorf("Type = %q, want %q (reason %q)", got.Type, c.want, got.Because)
			}
			if c.because != "" && got.Because != c.because {
				t.Errorf("Because = %q, want %q", got.Because, c.because)
			}
		})
	}
}

// A device that says what it is outranks a guess from its badge.
func TestModelBeatsVendor(t *testing.T) {
	in := InferType(types.Device{
		Vendor: "Raspberry Pi Trading Ltd", // would suggest a single-board computer
		Model:  "Pixma MG3600",             // but it says it is a printer
	}, nil, false)

	if in.Type != TypePrinter {
		t.Errorf("Type = %q, want %q", in.Type, TypePrinter)
	}
	if in.Because != ByModel {
		t.Errorf("Because = %q, want %q", in.Because, ByModel)
	}
}

// The gateway is the one signal that cannot be argued with.
func TestGatewayOverridesEverything(t *testing.T) {
	in := InferType(types.Device{
		Vendor: "Synology", Model: "DiskStation DS220+",
	}, []string{"_ipp._tcp"}, true)

	if in.Type != TypeRouter {
		t.Errorf("Type = %q, want %q, the default route is the router whatever else it does", in.Type, TypeRouter)
	}
}

// Multi-category manufacturers must not be classified from the badge, or the
// type column becomes something users learn to ignore.
func TestAmbiguousVendorsAreNotGuessed(t *testing.T) {
	for _, vendor := range []string{
		"Samsung Electronics Co.,Ltd", "Apple, Inc.", "LG Electronics",
		"Sony Corporation", "Intel Corporate", "Google, Inc.",
	} {
		if in := InferType(types.Device{Vendor: vendor}, nil, false); in.Type != TypeUnknown {
			t.Errorf("vendor %q alone was classified as %q; it makes several categories", vendor, in.Type)
		}
	}
}

// Confidence must actually order the rules, not merely be recorded.
func TestStrongerEvidenceWins(t *testing.T) {
	// _smb._tcp suggests a computer weakly; _ipp._tcp says printer strongly.
	in := InferType(types.Device{}, []string{"_smb._tcp", "_ipp._tcp"}, false)
	if in.Type != TypePrinter {
		t.Errorf("Type = %q, want %q", in.Type, TypePrinter)
	}
}

// Nothing known must produce nothing claimed.
func TestNoEvidenceProducesNoType(t *testing.T) {
	if in := InferType(types.Device{}, nil, false); in.Type != TypeUnknown {
		t.Errorf("Type = %q, want empty", in.Type)
	}
}
