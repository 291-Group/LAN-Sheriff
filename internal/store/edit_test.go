package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func seedDevice(t *testing.T, s *Store) string {
	t.Helper()
	id, err := s.ObserveDevice(context.Background(), types.Sighting{
		MAC: "AA:BB:CC:DD:EE:10", IP: "192.168.1.10", Source: "neighbour", SeenAt: time.Now(),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: %v", err)
	}
	return id
}

func str(v string) *string { return &v }

func netipNothing() netip.Addr { return netip.Addr{} }

func TestEditDeviceSetsTrustAndLabel(t *testing.T) {
	s := newTestStore(t)
	id := seedDevice(t, s)

	if err := s.EditDevice(context.Background(), id, DeviceEdit{
		Trust: str(types.TrustDeputized), Label: str("  Kitchen iPad  "), Notes: str("bought 2024"),
	}); err != nil {
		t.Fatalf("EditDevice: %v", err)
	}

	d := getDevice(t, s, id)
	if d.Trust != types.TrustDeputized {
		t.Errorf("Trust = %q, want %q", d.Trust, types.TrustDeputized)
	}
	// Surrounding whitespace is the user's typing, not their intent.
	if d.Label != "Kitchen iPad" {
		t.Errorf("Label = %q, want %q", d.Label, "Kitchen iPad")
	}
	if d.Notes != "bought 2024" {
		t.Errorf("Notes = %q", d.Notes)
	}
}

// An omitted field must be left alone, while an empty one clears. Without that
// distinction, saving a label would silently reset the trust level.
func TestEditDeviceLeavesOmittedFieldsAlone(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := seedDevice(t, s)

	if err := s.EditDevice(ctx, id, DeviceEdit{Trust: str(types.TrustWatched), Label: str("Front Door")}); err != nil {
		t.Fatal(err)
	}
	// A second edit mentioning only the notes.
	if err := s.EditDevice(ctx, id, DeviceEdit{Notes: str("replaced battery")}); err != nil {
		t.Fatal(err)
	}

	d := getDevice(t, s, id)
	if d.Trust != types.TrustWatched {
		t.Errorf("Trust = %q; an unrelated edit reset it", d.Trust)
	}
	if d.Label != "Front Door" {
		t.Errorf("Label = %q; an unrelated edit cleared it", d.Label)
	}
	if d.Notes != "replaced battery" {
		t.Errorf("Notes = %q", d.Notes)
	}
}

func TestEditDeviceClearingIsDistinctFromOmitting(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := seedDevice(t, s)

	s.EditDevice(ctx, id, DeviceEdit{Label: str("Temporary")})
	if err := s.EditDevice(ctx, id, DeviceEdit{Label: str("")}); err != nil {
		t.Fatal(err)
	}
	if d := getDevice(t, s, id); d.Label != "" {
		t.Errorf("Label = %q, want it cleared", d.Label)
	}
}

// A type the user set must survive re-inference, or they would have to keep
// correcting the same wrong guess.
func TestManualTypeSurvivesReinference(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := seedDevice(t, s)

	if err := s.EditDevice(ctx, id, DeviceEdit{DeviceType: str("camera")}); err != nil {
		t.Fatal(err)
	}
	d := getDevice(t, s, id)
	if !d.TypeLocked {
		t.Fatal("setting a type by hand did not lock it")
	}
	if d.TypeReason != ReasonManual {
		t.Errorf("TypeReason = %q, want %q", d.TypeReason, ReasonManual)
	}

	if _, err := s.RefreshDeviceTypes(ctx, netipNothing()); err != nil {
		t.Fatal(err)
	}
	if again := getDevice(t, s, id); again.DeviceType != "camera" {
		t.Errorf("DeviceType = %q after re-inference, want the user's choice", again.DeviceType)
	}
}

// Clearing the type hands the decision back to inference.
func TestClearingTypeUnlocksIt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := seedDevice(t, s)

	s.EditDevice(ctx, id, DeviceEdit{DeviceType: str("camera")})
	if err := s.EditDevice(ctx, id, DeviceEdit{DeviceType: str("")}); err != nil {
		t.Fatal(err)
	}
	if d := getDevice(t, s, id); d.TypeLocked {
		t.Error("clearing the type left it locked, so inference can never fill it")
	}
}

func TestEditDeviceRejectsUnknownTrustAndMissingDevice(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := seedDevice(t, s)

	if err := s.EditDevice(ctx, id, DeviceEdit{Trust: str("friendly")}); err == nil {
		t.Error("an unknown trust level was accepted")
	}
	if err := s.EditDevice(ctx, "no-such-device", DeviceEdit{Label: str("x")}); err == nil {
		t.Error("editing a device that does not exist reported success")
	}
}
