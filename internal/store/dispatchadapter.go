package store

import (
	"context"
	"fmt"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/dispatch"
)

// The adapter between the store and The Dispatch.
//
// It exists so `internal/dispatch` can define a narrow interface in its own
// terms and be tested against a map, rather than depending on the database. The
// translation is deliberately dull: anything clever here would be logic living
// outside both packages' tests.

// DispatchPeers implements dispatch.Store.
func (s *Store) DispatchPeers(ctx context.Context) ([]dispatch.PeerRecord, error) {
	peers, err := s.Peers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]dispatch.PeerRecord, 0, len(peers))
	for _, p := range peers {
		out = append(out, dispatch.PeerRecord{
			PeerID:    p.PeerID,
			PublicKey: p.PublicKey,
			Label:     p.Label,
			Suspended: p.Trust == PeerSuspended,
			LastAddr:  p.LastAddr,
		})
	}
	return out, nil
}

// MergeDispatchSummaries implements dispatch.Store.
//
// peerID comes from the authenticated connection, and is passed through to
// MergePeerSummaries, which refuses any bucket claiming to belong to somebody
// else. The buckets arrive already sanitized by the wire layer; this converts
// them and nothing more.
func (s *Store) MergeDispatchSummaries(ctx context.Context, peerID string,
	buckets []dispatch.SummaryBucket, now time.Time) (int, error) {

	rows := make([]PeerSummary, 0, len(buckets))
	for _, b := range buckets {
		rows = append(rows, PeerSummary{
			Device: b.Device, Hour: b.Hour, Org: b.Org, Country: b.Country,
			ASN: b.ASN, App: b.App, Proto: b.Proto, Port: b.Port,
			Flows: b.Flows, BytesOut: b.BytesOut, BytesIn: b.BytesIn,
		})
	}
	return s.MergePeerSummaries(ctx, peerID, rows, now)
}

// Compile-time proof that the store satisfies what the service needs. Without
// this the mismatch would only appear when somebody wired the two together.
var _ dispatch.Store = (*Store)(nil)

// AddDispatchPeer implements dispatch.Store, recording a completed pairing.
func (s *Store) AddDispatchPeer(ctx context.Context, p dispatch.PairedPeer) error {
	return s.AddPeer(ctx, Peer{
		PeerID:    p.PeerID,
		PublicKey: p.PublicKey,
		Label:     p.Label,
		Trust:     PeerTrusted,
		LastAddr:  p.Addr,
	})
}

// LocalSummaries builds the aggregates this instance offers to its peers.
//
// **This is the sending half of the exchange, and it was missing for a while:**
// the receive path, the wire format and the merge were all built and tested
// while nothing ever produced a bucket, so two paired instances connected and
// shared nothing. The lesson is the one this project keeps relearning, a
// feature is not the sum of its halves until something calls both.
//
// Only outbound flows, aggregated to the hour. Nothing that identifies a
// destination beyond its organization and country leaves this machine: no
// address, no hostname, no process path. See docs/DISPATCH-PROTOCOL.md §D-5.
func (s *Store) LocalSummaries(ctx context.Context, since time.Time, limit int) ([]dispatch.SummaryBucket, error) {
	if limit <= 0 || limit > dispatch.MaxBuckets {
		limit = dispatch.MaxBuckets
	}

	// GROUP BY is positional. SQLite resolves a bare name against output
	// aliases before input columns, which has silently grouped by the wrong
	// thing in this codebase before.
	rows, err := s.db.QueryContext(ctx, `
SELECT COALESCE(f.device_id, ''),
       (f.ts_last / 3600) * 3600,
       COALESCE(e.org, ''), COALESCE(e.country, ''), COALESCE(e.asn, 0),
       COALESCE(f.process, ''), COALESCE(f.proto, ''), COALESCE(f.dst_port, 0),
       COUNT(*), COALESCE(SUM(f.bytes_out), 0), COALESCE(SUM(f.bytes_in), 0)
FROM flows f
LEFT JOIN endpoints e ON e.ip = f.dst_ip
WHERE f.ts_last >= ? AND f.direction = 'out'
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8
ORDER BY 2 DESC
LIMIT ?`, since.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("store: building local summaries: %w", err)
	}
	defer rows.Close()

	var out []dispatch.SummaryBucket
	for rows.Next() {
		var b dispatch.SummaryBucket
		if err := rows.Scan(&b.Device, &b.Hour, &b.Org, &b.Country, &b.ASN,
			&b.App, &b.Proto, &b.Port, &b.Flows, &b.BytesOut, &b.BytesIn); err != nil {
			return nil, err
		}
		// A bucket with no device cannot be attributed on the far side, and the
		// receiver would drop it anyway.
		if b.Device == "" {
			continue
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// SetDispatchPeerAddr implements dispatch.Store.
func (s *Store) SetDispatchPeerAddr(ctx context.Context, peerID, addr string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE peers SET last_addr = ? WHERE peer_id = ?`, addr, peerID)
	if err != nil {
		return fmt.Errorf("store: recording peer address: %w", err)
	}
	return nil
}

// SetDispatchPeerLabelIfEmpty implements dispatch.Store.
//
// The WHERE clause carries the whole rule: a peer this machine has already
// named keeps that name, however often the far end announces its own.
func (s *Store) SetDispatchPeerLabelIfEmpty(ctx context.Context, peerID, label string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE peers SET label = ? WHERE peer_id = ? AND COALESCE(label, '') = ''`,
		label, peerID)
	if err != nil {
		return fmt.Errorf("store: recording peer name: %w", err)
	}
	return nil
}

// RenamePeer sets the name shown for a peer on this machine only.
//
// Unconditional, unlike SetDispatchPeerLabelIfEmpty: this is the operator
// speaking, and they outrank whatever the far end calls itself. It is also the
// answer to a machine that cannot describe itself, which is commoner than it
// sounds. A container's hostname is its id, and a machine nobody has named is
// "localhost"; both arrive here as no name at all, and without a way to set one
// the peer would be a fingerprint forever.
//
// An empty name is allowed and means "go back to whatever it calls itself".
func (s *Store) RenamePeer(ctx context.Context, peerID, label string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE peers SET label = ? WHERE peer_id = ?`, label, peerID); err != nil {
		return fmt.Errorf("store: renaming peer: %w", err)
	}
	return nil
}

// ExpireDispatchSummaries implements dispatch.Store.
func (s *Store) ExpireDispatchSummaries(ctx context.Context, ttl time.Duration, now time.Time) (int64, error) {
	return s.ExpirePeerSummaries(ctx, ttl, now)
}
