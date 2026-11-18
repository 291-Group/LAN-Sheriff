package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/store"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// stallingWriter fails every write while stalled is set, and records what it
// was given when it is not. It stands in for an SD card that has stopped
// answering.
type stallingWriter struct {
	stalled   bool
	flows     [][]types.Flow
	dns       [][]types.DNSEvent
	endpoints []map[string]store.EndpointSighting
}

var errStalled = errors.New("database is locked (5) (SQLITE_BUSY)")

func (w *stallingWriter) TouchEndpoints(_ context.Context, seen map[string]store.EndpointSighting) error {
	if w.stalled {
		return errStalled
	}
	w.endpoints = append(w.endpoints, seen)
	return nil
}

func (w *stallingWriter) WriteFlows(_ context.Context, flows []types.Flow) error {
	if w.stalled {
		return errStalled
	}
	w.flows = append(w.flows, flows)
	return nil
}

func (w *stallingWriter) WriteDNS(_ context.Context, events []types.DNSEvent) error {
	if w.stalled {
		return errStalled
	}
	w.dns = append(w.dns, events)
	return nil
}

func testEngine(w storeWriter) *Engine {
	e := NewEngine(nil, NewBus(16), nil)
	e.writer = w
	return e
}

// testFlow builds a flow the engine keys by its start time, as the
// normalizer would have keyed it by its addresses; the port keeps two flows
// in the same test distinct.
func testFlow(dst string, port int, at time.Time) types.Flow {
	at = at.Add(time.Duration(port) * time.Second)
	return types.Flow{
		TSStart: at, TSLast: at, DeviceID: "self-test",
		SrcIP: "192.168.1.5", SrcPort: uint16(40000 + port), DstIP: dst, DstPort: 443,
		Proto: types.ProtoTCP, Direction: types.DirOut, Active: true,
	}
}

// A stalled store costs time, not observations: everything staged while it
// was failing lands once it recovers, each exactly once.
func TestFlushHoldsBatchesWhileStorageStalls(t *testing.T) {
	w := &stallingWriter{stalled: true}
	e := testEngine(w)
	ctx := context.Background()
	now := time.Now()

	e.record(FlowEvent{Phase: PhaseOpen, Flow: testFlow("93.184.216.34", 1, now)})
	e.recordDNS(&types.DNSEvent{TS: now, QName: "one.example", DeviceID: "self-test"})
	e.flush(ctx) // fails; held
	if len(w.flows) != 0 {
		t.Fatal("flows written through a stalled store")
	}
	if e.flushDelay != 2*FlushInterval {
		t.Errorf("after one failure flushDelay = %v, want %v", e.flushDelay, 2*FlushInterval)
	}
	if e.Health().Healthy() {
		t.Error("health reports healthy while writes fail")
	}

	// More arrives during the stall, including a newer state of the held flow.
	newer := testFlow("93.184.216.34", 1, now)
	newer.TSLast = newer.TSStart.Add(time.Second)
	newer.BytesOut = 999
	e.record(FlowEvent{Phase: PhaseUpdate, Flow: newer})
	e.record(FlowEvent{Phase: PhaseOpen, Flow: testFlow("93.184.216.35", 2, now)})
	e.recordDNS(&types.DNSEvent{TS: now, QName: "two.example", DeviceID: "self-test"})
	e.flush(ctx) // fails again; still held
	if e.flushDelay != 4*FlushInterval {
		t.Errorf("after two failures flushDelay = %v, want %v", e.flushDelay, 4*FlushInterval)
	}

	w.stalled = false
	e.flush(ctx)

	if len(w.flows) != 1 {
		t.Fatalf("recovered flush wrote %d batches, want 1", len(w.flows))
	}
	got := map[string]types.Flow{}
	for _, f := range w.flows[0] {
		got[f.DstIP] = f
	}
	if len(got) != 2 {
		t.Errorf("recovered batch has %d flows, want 2: %+v", len(got), w.flows[0])
	}
	if f := got["93.184.216.34"]; f.BytesOut != 999 {
		t.Errorf("held flow was not superseded by its newer state: %+v", f)
	}
	if len(w.dns) != 1 || len(w.dns[0]) != 2 {
		t.Errorf("recovered DNS = %v, want one batch of 2", w.dns)
	} else if w.dns[0][0].QName != "one.example" {
		t.Errorf("held DNS events lost their order: %v", w.dns[0])
	}
	if len(w.endpoints) != 1 {
		t.Errorf("endpoint batches written = %d, want 1", len(w.endpoints))
	} else if _, ok := w.endpoints[0]["93.184.216.35"]; !ok {
		t.Error("endpoint sighting from during the stall was lost")
	}
	if e.flushDelay != FlushInterval {
		t.Errorf("after recovery flushDelay = %v, want %v", e.flushDelay, FlushInterval)
	}
	if !e.Health().Healthy() {
		t.Error("health still unhealthy after a successful write")
	}

	// Nothing is written twice.
	e.flush(ctx)
	if len(w.flows) != 1 || len(w.dns) != 1 {
		t.Error("an empty flush wrote something")
	}
}

// The delay climbs to the ceiling and no further.
func TestFlushBackoffIsBounded(t *testing.T) {
	w := &stallingWriter{stalled: true}
	e := testEngine(w)
	ctx := context.Background()
	e.record(FlowEvent{Phase: PhaseOpen, Flow: testFlow("93.184.216.34", 1, time.Now())})
	for i := 0; i < 10; i++ {
		e.flush(ctx)
	}
	if e.flushDelay != MaxFlushInterval {
		t.Errorf("after many failures flushDelay = %v, want the ceiling %v", e.flushDelay, MaxFlushInterval)
	}
}

// Memory, not the card, is the scarce thing on a router: a stall that goes on
// long enough costs the newest observations and never the process.
func TestHeldObservationsAreBounded(t *testing.T) {
	w := &stallingWriter{stalled: true}
	e := testEngine(w)
	now := time.Now()
	for i := 0; i < maxPendingDNS+50; i++ {
		e.recordDNS(&types.DNSEvent{TS: now, QName: "x.example"})
	}
	if len(e.pendingDNS) != maxPendingDNS {
		t.Errorf("pendingDNS = %d, want capped at %d", len(e.pendingDNS), maxPendingDNS)
	}
	if e.dropped != 50 {
		t.Errorf("dropped = %d, want 50", e.dropped)
	}
	// A failed flush puts the batch back, still at the cap, and what arrives
	// while it is held is what gives way: the record ends, it does not get a
	// hole in the middle.
	e.flush(context.Background())
	if n := len(e.pendingDNS); n != maxPendingDNS {
		t.Errorf("held DNS after a failed flush = %d, want %d", n, maxPendingDNS)
	}
	e.recordDNS(&types.DNSEvent{TS: now, QName: "newest.example"})
	if e.dropped != 1 {
		t.Errorf("dropped after one arrival at the cap = %d, want 1", e.dropped)
	}
	e.flush(context.Background())
	if n := len(e.pendingDNS); n != maxPendingDNS {
		t.Errorf("held DNS after a second failed flush = %d, want %d", n, maxPendingDNS)
	}
	if first := e.pendingDNS[0].QName; first != "x.example" {
		t.Errorf("the held batch lost its head: first is %q", first)
	}
}
