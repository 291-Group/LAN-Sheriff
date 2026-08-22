package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Storage for The Dispatch: paired peers and the summaries they report.
//
// The merge rules this file enforces are docs/DISPATCH-PROTOCOL.md §8. They
// exist for one adversary (a paired peer that has since been compromised) and
// the reasoning behind each is in that document rather than repeated here.
//
// The single most important property is that **a peer can only ever write rows
// belonging to itself**. That is enforced twice: by the primary key, which
// begins with peer_id, and by refusing a peer identifier the caller did not
// authenticate. Two mechanisms because this is the one rule whose failure would
// let a compromised machine fabricate evidence against a different machine.

// Peer trust states.
const (
	// PeerTrusted merges and displays the peer's data.
	PeerTrusted = "trusted"
	// PeerSuspended keeps the pairing and the connection, and stops believing
	// anything the peer says. Unpairing would mean losing the ability to watch a
	// machine at exactly the moment it became interesting.
	PeerSuspended = "suspended"
)

// ErrUnknownPeer is returned when a write names a peer that is not paired.
var ErrUnknownPeer = errors.New("store: peer is not paired")

// ErrPeerSuspended is returned when a suspended peer reports data.
var ErrPeerSuspended = errors.New("store: peer is suspended")

// Peer is a paired instance.
type Peer struct {
	PeerID    string    `json:"peer_id"`
	PublicKey []byte    `json:"-"` // never leaves the process
	Label     string    `json:"label,omitempty"`
	Trust     string    `json:"trust"`
	PairedAt  time.Time `json:"paired_at"`
	LastSeen  time.Time `json:"last_seen"`
	LastAddr  string    `json:"last_addr,omitempty"`
	ClockSkew int       `json:"clock_skew_secs"`
}

// PeerSummary is one merged bucket, as stored.
type PeerSummary struct {
	PeerID  string
	Device  string
	Hour    int64
	Org     string
	Country string
	ASN     int
	App     string
	Proto   string
	Port    uint16

	Flows    int64
	BytesOut int64
	BytesIn  int64
}

// AddPeer records a pairing.
func (s *Store) AddPeer(ctx context.Context, p Peer) error {
	if p.PeerID == "" || len(p.PublicKey) == 0 {
		return errors.New("store: a peer needs an identifier and a key")
	}
	if p.Trust == "" {
		p.Trust = PeerTrusted
	}
	if p.PairedAt.IsZero() {
		p.PairedAt = time.Now()
	}
	// Written before the pairing, so a ledger failure fails the pairing rather
	// than producing one that is not on the record.
	if err := s.logPairing(ctx, "paired", p.PeerID, p.Label, p.LastAddr); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO peers (peer_id, public_key, label, trust, paired_at, last_addr)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(peer_id) DO UPDATE SET
  public_key = excluded.public_key,
  label      = COALESCE(NULLIF(excluded.label, ''), peers.label),
  last_addr  = COALESCE(NULLIF(excluded.last_addr, ''), peers.last_addr)`,
		p.PeerID, p.PublicKey, p.Label, p.Trust, p.PairedAt.Unix(), p.LastAddr)
	if err != nil {
		return fmt.Errorf("store: adding peer: %w", err)
	}
	return nil
}

// Peers lists paired instances.
func (s *Store) Peers(ctx context.Context) ([]Peer, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT peer_id, public_key, COALESCE(label, ''), trust, paired_at, last_seen,
       COALESCE(last_addr, ''), clock_skew
FROM peers ORDER BY COALESCE(NULLIF(label, ''), peer_id)`)
	if err != nil {
		return nil, fmt.Errorf("store: listing peers: %w", err)
	}
	defer rows.Close()

	var out []Peer
	for rows.Next() {
		var (
			p                 Peer
			pairedAt, lastSee int64
		)
		if err := rows.Scan(&p.PeerID, &p.PublicKey, &p.Label, &p.Trust,
			&pairedAt, &lastSee, &p.LastAddr, &p.ClockSkew); err != nil {
			return nil, err
		}
		p.PairedAt = time.Unix(pairedAt, 0)
		if lastSee > 0 {
			p.LastSeen = time.Unix(lastSee, 0)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetPeerTrust moves a peer between trusted and suspended.
func (s *Store) SetPeerTrust(ctx context.Context, peerID, trust string) error {
	if trust != PeerTrusted && trust != PeerSuspended {
		return fmt.Errorf("store: unknown trust state %q", trust)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE peers SET trust = ? WHERE peer_id = ?`, trust, peerID)
	if err != nil {
		return fmt.Errorf("store: setting peer trust: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrUnknownPeer, peerID)
	}
	return nil
}

// RemovePeer unpairs and deletes everything that peer ever reported.
//
// Both, together, in one transaction. An unpairing that left the data behind
// would mean the operator's decision to stop trusting a machine had no visible
// effect, which is the opposite of what the action means.
func (s *Store) RemovePeer(ctx context.Context, peerID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM peer_summaries WHERE peer_id = ?`, peerID); err != nil {
		return fmt.Errorf("store: removing peer data: %w", err)
	}
	// In the same transaction, so the record of the unpairing cannot be lost
	// along with the peer it describes.
	var label, addr string
	_ = tx.QueryRowContext(ctx,
		`SELECT COALESCE(label, ''), COALESCE(last_addr, '') FROM peers WHERE peer_id = ?`,
		peerID).Scan(&label, &addr)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pairing_log (ts, peer_id, label, event, addr) VALUES (?, ?, ?, 'unpaired', ?)`,
		time.Now().Unix(), peerID, label, addr); err != nil {
		return fmt.Errorf("store: recording the unpairing: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM peers WHERE peer_id = ?`, peerID); err != nil {
		return fmt.Errorf("store: removing peer: %w", err)
	}
	return tx.Commit()
}

// PairingEvent is one entry in the ledger.
type PairingEvent struct {
	At    time.Time `json:"at"`
	Peer  string    `json:"peer_id"`
	Label string    `json:"label,omitempty"`
	Event string    `json:"event"`
	Addr  string    `json:"addr,omitempty"`
}

func (s *Store) logPairing(ctx context.Context, event, peerID, label, addr string) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO pairing_log (ts, peer_id, label, event, addr) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), peerID, label, event, addr); err != nil {
		return fmt.Errorf("store: recording the pairing: %w", err)
	}
	return nil
}

// LogPeeringChange records that sharing was switched on or off.
//
// In the same ledger as pairings, because the question somebody asks is "was
// this machine ever sharing", and an answer that lists pairings but not the
// times sharing itself was turned on is only part of it.
func (s *Store) LogPeeringChange(ctx context.Context, on bool) error {
	event := "sharing_off"
	if on {
		event = "sharing_on"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pairing_log (ts, peer_id, label, event, addr) VALUES (?, '', '', ?, '')`,
		time.Now().Unix(), event)
	if err != nil {
		return fmt.Errorf("store: recording the sharing change: %w", err)
	}
	return nil
}

// PairingHistory returns every pairing and unpairing this install has seen,
// most recent first.
//
// Deliberately not filtered by whether the peer still exists: the entries for
// peers that were removed are the ones worth reading.
func (s *Store) PairingHistory(ctx context.Context, limit int) ([]PairingEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT ts, peer_id, COALESCE(label, ''), event, COALESCE(addr, '')
FROM pairing_log ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PairingEvent
	for rows.Next() {
		var e PairingEvent
		var ts int64
		if err := rows.Scan(&ts, &e.Peer, &e.Label, &e.Event, &e.Addr); err != nil {
			return nil, err
		}
		e.At = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// MergePeerSummaries stores buckets reported by one authenticated peer.
//
// peerID comes from the transport, which learned it from the pinned key that
// completed the TLS handshake. It is never taken from the message body: a peer
// that could name itself could name somebody else.
//
// Counts are **replaced, not accumulated**. A peer reporting the same hour twice
// is restating a total it recomputed, not adding a second observation, and
// summing would let a peer inflate its own numbers without limit simply by
// resending.
func (s *Store) MergePeerSummaries(ctx context.Context, peerID string, buckets []PeerSummary, now time.Time) (int, error) {
	if len(buckets) == 0 {
		return 0, nil
	}

	// Rule 2, checked in code as well as expressed in the primary key. The key
	// alone would already keep the rows apart; this makes an attempt to cross
	// the boundary an error rather than a silently misfiled row.
	for i, b := range buckets {
		if b.PeerID != "" && b.PeerID != peerID {
			return 0, fmt.Errorf(
				"store: peer %s tried to write a summary attributed to %s (bucket %d); "+
					"a peer may only report about itself",
				peerID, b.PeerID, i)
		}
	}

	var trust string
	err := s.db.QueryRowContext(ctx,
		`SELECT trust FROM peers WHERE peer_id = ?`, peerID).Scan(&trust)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, fmt.Errorf("%w: %s", ErrUnknownPeer, peerID)
	case err != nil:
		return 0, err
	case trust == PeerSuspended:
		// Not an error the caller should close a connection over: the operator
		// chose this, and the peer is behaving normally.
		return 0, ErrPeerSuspended
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO peer_summaries
  (peer_id, device, hour, org, country, asn, app, proto, port,
   flows, bytes_out, bytes_in, received_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(peer_id, device, hour, org, app, proto, port) DO UPDATE SET
  flows       = excluded.flows,
  bytes_out   = excluded.bytes_out,
  bytes_in    = excluded.bytes_in,
  country     = excluded.country,
  asn         = excluded.asn,
  received_at = excluded.received_at`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	ts := now.Unix()
	for _, b := range buckets {
		if _, err := stmt.ExecContext(ctx,
			peerID, b.Device, b.Hour, b.Org, b.Country, b.ASN, b.App, b.Proto, b.Port,
			b.Flows, b.BytesOut, b.BytesIn, ts); err != nil {
			return 0, fmt.Errorf("store: merging peer summary: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE peers SET last_seen = ? WHERE peer_id = ?`, ts, peerID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(buckets), nil
}

// PeerSummariesSince returns merged buckets from trusted peers only.
//
// The trust filter lives in the query rather than in the caller. A suspended
// peer's rows stay on disk, suspension is reversible, and re-fetching a day of
// history on un-suspending would be worse, so every read path must exclude
// them, and the reliable way to guarantee that is to make the join do it.
func (s *Store) PeerSummariesSince(ctx context.Context, since time.Time) ([]PeerSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ps.peer_id, ps.device, ps.hour, ps.org, ps.country, ps.asn,
       ps.app, ps.proto, ps.port, ps.flows, ps.bytes_out, ps.bytes_in
FROM peer_summaries ps
JOIN peers p ON p.peer_id = ps.peer_id
WHERE ps.hour >= ? AND p.trust = ?
ORDER BY ps.hour DESC`, since.Unix(), PeerTrusted)
	if err != nil {
		return nil, fmt.Errorf("store: reading peer summaries: %w", err)
	}
	defer rows.Close()

	var out []PeerSummary
	for rows.Next() {
		var b PeerSummary
		if err := rows.Scan(&b.PeerID, &b.Device, &b.Hour, &b.Org, &b.Country,
			&b.ASN, &b.App, &b.Proto, &b.Port, &b.Flows, &b.BytesOut, &b.BytesIn); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ExpirePeerSummaries drops peer data past its time to live.
//
// Peer data is a cache, not a record. This instance's own observations are the
// only thing it treats as durable truth.
func (s *Store) ExpirePeerSummaries(ctx context.Context, ttl time.Duration, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM peer_summaries WHERE received_at < ?`, now.Add(-ttl).Unix())
	if err != nil {
		return 0, fmt.Errorf("store: expiring peer summaries: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PeerDestination is one organization a peer has reached, aggregated for
// display.
//
// Deliberately not a `types.Endpoint`: an endpoint is an address, and peer data
// has none. Giving this the same shape would invite code that treats the two
// alike and then reaches for a field that is always empty.
type PeerDestination struct {
	PeerID  string  `json:"peer_id"`
	Label   string  `json:"label,omitempty"`
	Device  string  `json:"device"`
	Org     string  `json:"org,omitempty"`
	Country string  `json:"country,omitempty"`
	ASN     int     `json:"asn,omitempty"`
	App     string  `json:"app,omitempty"`
	Flows   int64   `json:"flows"`
	Bytes   int64   `json:"bytes"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`

	// LastHour is the most recent hour this peer reported the destination in.
	//
	// Peer data is aggregated into hourly buckets, so this is an hour rather
	// than a moment, and it is the honest resolution: claiming a timestamp
	// would imply a precision the protocol deliberately does not carry.
	//
	// It was missing entirely, and its absence was the whole problem: a
	// destination from a peer sat in the list beside local ones with no way to
	// tell whether it happened minutes ago or was the last thing that peer
	// managed to send before it went offline yesterday.
	LastHour time.Time `json:"last_hour,omitempty"`
}

// PeerDestinations aggregates what trusted peers have reported since a time,
// grouped for the map and the destination list.
//
// Suspended peers are excluded by the join, as everywhere else: a read path that
// forgot the trust filter would silently reintroduce data the operator chose to
// stop believing.
func (s *Store) PeerDestinations(ctx context.Context, since time.Time, limit int) ([]PeerDestination, error) {
	if limit <= 0 {
		limit = 500
	}
	// GROUP BY is positional; see the note in LocalSummaries.
	rows, err := s.db.QueryContext(ctx, `
SELECT ps.peer_id, COALESCE(NULLIF(p.label, ''), ps.peer_id), ps.device,
       ps.org, ps.country, ps.asn, ps.app,
       SUM(ps.flows), SUM(ps.bytes_out + ps.bytes_in), MAX(ps.hour)
FROM peer_summaries ps
JOIN peers p ON p.peer_id = ps.peer_id
WHERE ps.hour >= ? AND p.trust = ?
GROUP BY 1, 2, 3, 4, 5, 6, 7
ORDER BY 8 DESC
LIMIT ?`, since.Unix(), PeerTrusted, limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading peer destinations: %w", err)
	}
	defer rows.Close()

	out := make([]PeerDestination, 0, 64)
	for rows.Next() {
		var d PeerDestination
		var lastHour int64
		if err := rows.Scan(&d.PeerID, &d.Label, &d.Device, &d.Org, &d.Country,
			&d.ASN, &d.App, &d.Flows, &d.Bytes, &lastHour); err != nil {
			return nil, err
		}
		if lastHour > 0 {
			d.LastHour = time.Unix(lastHour, 0).UTC()
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
