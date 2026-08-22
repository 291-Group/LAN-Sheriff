package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/discover"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// keys derives the identity keys this observation supports.
func observationKeys(o types.Sighting) []identityKey {
	var keys []identityKey

	if mac := discover.NormalizeMAC(o.MAC); len(mac) == 12 && mac != "000000000000" {
		kind := KeyMAC
		if discover.IsRandomized(o.MAC) {
			kind = KeyRandomMAC
		}
		keys = append(keys, identityKey{Kind: kind, Value: mac})
	}
	if h := normalizeHostname(o.Hostname); h != "" {
		keys = append(keys, identityKey{Kind: KeyHostname, Value: h})
	}
	sortKeys(keys)
	return keys
}

// ObserveDevice records a sighting, creating, updating or merging device records
// as the evidence requires. It returns the device's stable ID.
//
// An observation carrying no identity key at all is not an error: a flow seen
// from an address nobody has named yet is still worth attributing, so the
// address alone is used to find an existing device, and otherwise nothing is
// created. Inventing a device per unnamed address would fill the Roster with
// rows that can never be merged.
func (s *Store) ObserveDevice(ctx context.Context, o types.Sighting) (string, error) {
	if o.SeenAt.IsZero() {
		o.SeenAt = time.Now()
	}
	keys := observationKeys(o)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck // rolled back only if Commit did not run

	id, err := resolveDevice(ctx, tx, keys, o.IP, o.MAC)
	if err != nil {
		return "", err
	}
	arrived := false
	if id == "" {
		if len(keys) == 0 {
			return "", nil // nothing to identify it by, and nothing invented
		}
		id = o.PreferredID
		if id == "" {
			id = newDeviceID()
		}
		arrived = true
	}

	if err := writeDevice(ctx, tx, id, o); err != nil {
		return "", err
	}
	for _, k := range keys {
		if err := writeKey(ctx, tx, id, k, o.SeenAt); err != nil {
			return "", err
		}
	}
	if o.IP != "" {
		if err := writeAddress(ctx, tx, id, o.IP, o.SeenAt); err != nil {
			return "", err
		}
	}
	for _, svc := range o.Services {
		if err := writeService(ctx, tx, id, svc, o.Source, o.SeenAt); err != nil {
			return "", err
		}
	}

	// Raised inside the same transaction as the device row, so a finding can
	// never exist for a device that was rolled back.
	if arrived {
		if err := s.recordNewDevice(ctx, tx, id, o); err != nil {
			return "", err
		}
	}

	return id, tx.Commit()
}

// resolveDevice finds the device an observation belongs to, merging records when
// the observation proves two of them are the same machine.
//
// The merging case is the one that matters. The neighbour table sees a hardware
// address; mDNS sees a hostname; until something reports both together they are
// two rows. When that something arrives, the rows must become one, otherwise a
// roster slowly fills with duplicates of the same phone.
func resolveDevice(ctx context.Context, tx *sql.Tx, keys []identityKey, ip, observedMAC string) (string, error) {
	matched, err := devicesForKeys(ctx, tx, keys)
	if err != nil {
		return "", err
	}

	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		// Fall through to the address.
	default:
		return mergeDevices(ctx, tx, matched)
	}

	// No identity key matched. The address is the remaining evidence, and it is
	// good evidence *at a moment in time*: two sources describing the same
	// address seconds apart are describing the same machine, because DHCP
	// reassigns over hours and days.
	//
	// This path is not an edge case, it is the normal one. The neighbour table
	// reports a hardware address and an IP; mDNS reports a hostname and an IP;
	// neither can report both, because a socket cannot see the sender's hardware
	// address. Without resolving by address the two would never converge and every
	// device would appear twice.
	if ip == "" {
		return "", nil
	}
	candidate, candidateMAC, err := deviceForAddress(ctx, tx, ip)
	if err != nil || candidate == "" {
		return "", err
	}

	// One thing overrides the address: a hardware address that disagrees. A MAC is
	// authoritative for identity, so if this observation carries one and the
	// device holding the address carries a different one, the address has been
	// reassigned to a new machine. Adopting it there would weld two unrelated
	// devices together, and weeks of lease churn would do it repeatedly.
	obsMAC := discover.NormalizeMAC(observedMAC)
	if obsMAC != "" && candidateMAC != "" && obsMAC != discover.NormalizeMAC(candidateMAC) {
		return "", nil
	}
	return candidate, nil
}

// devicesForKeys returns the distinct device IDs any of these keys point at,
// oldest first so a merge has a deterministic survivor.
func devicesForKeys(ctx context.Context, tx *sql.Tx, keys []identityKey) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(keys))
	placeholders := ""
	for i, k := range keys {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args = append(args, k.String())
	}

	rows, err := tx.QueryContext(ctx, `
SELECT DISTINCT k.device_id
FROM device_keys k
JOIN devices d ON d.id = k.device_id
WHERE k.key IN (`+placeholders+`)
ORDER BY d.first_seen ASC, d.id ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// deviceForAddress finds the device most recently seen at an address, and the
// hardware address that device is recorded under.
//
// Only the most recent holder counts: DHCP hands an address to a different
// machine eventually, and attributing new traffic to the previous owner would be
// worse than not attributing it at all. The MAC comes back with it so the caller
// can detect exactly that handover.
func deviceForAddress(ctx context.Context, tx *sql.Tx, ip string) (id, mac string, err error) {
	err = tx.QueryRowContext(ctx, `
SELECT a.device_id, COALESCE(d.mac, '')
FROM device_addresses a
JOIN devices d ON d.id = a.device_id
WHERE a.ip = ? ORDER BY a.last_seen DESC LIMIT 1`, ip).Scan(&id, &mac)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return id, mac, err
}

// mergeDevices folds several records into one, and returns the survivor.
//
// The oldest record survives, so a device's first_seen keeps meaning "when this
// machine first appeared" rather than resetting whenever new evidence arrives.
// Everything pointing at the absorbed records is repointed: identity keys,
// addresses, services, and the flows and DNS events already attributed to them.
func mergeDevices(ctx context.Context, tx *sql.Tx, ids []string) (string, error) {
	survivor, absorbed := ids[0], ids[1:]

	for _, old := range absorbed {
		// Carry over any field the survivor lacks. A merge should never lose
		// information that only the absorbed record had.
		if _, err := tx.ExecContext(ctx, `
UPDATE devices SET
  mac         = COALESCE(NULLIF(mac, ''),         (SELECT mac         FROM devices WHERE id = ?)),
  hostname    = COALESCE(NULLIF(hostname, ''),    (SELECT hostname    FROM devices WHERE id = ?)),
  name        = COALESCE(NULLIF(name, ''),        (SELECT name        FROM devices WHERE id = ?)),
  model       = COALESCE(NULLIF(model, ''),       (SELECT model       FROM devices WHERE id = ?)),
  vendor      = COALESCE(NULLIF(vendor, ''),      (SELECT vendor      FROM devices WHERE id = ?)),
  device_type = COALESCE(NULLIF(device_type, ''), (SELECT device_type FROM devices WHERE id = ?)),
  label       = COALESCE(NULLIF(label, ''),       (SELECT label       FROM devices WHERE id = ?)),
  notes       = COALESCE(NULLIF(notes, ''),       (SELECT notes       FROM devices WHERE id = ?)),
  first_seen  = MIN(first_seen, (SELECT first_seen FROM devices WHERE id = ?)),
  last_seen   = MAX(last_seen,  (SELECT last_seen  FROM devices WHERE id = ?)),
  is_self     = MAX(is_self,    (SELECT is_self    FROM devices WHERE id = ?)),
  suspicion   = MAX(suspicion,  (SELECT suspicion  FROM devices WHERE id = ?))
WHERE id = ?`,
			old, old, old, old, old, old, old, old, old, old, old, old, survivor); err != nil {
			return "", fmt.Errorf("merge fields: %w", err)
		}

		// Repoint everything that referenced the absorbed record. The OR REPLACE
		// on keys and OR IGNORE on the composite-key tables handle the case where
		// both records already hold the same row.
		for _, stmt := range []string{
			`UPDATE OR REPLACE device_keys      SET device_id = ? WHERE device_id = ?`,
			`UPDATE OR IGNORE  device_addresses SET device_id = ? WHERE device_id = ?`,
			`UPDATE OR IGNORE  device_services  SET device_id = ? WHERE device_id = ?`,
			`UPDATE            flows            SET device_id = ? WHERE device_id = ?`,
			`UPDATE            dns_events        SET device_id = ? WHERE device_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, stmt, survivor, old); err != nil {
				return "", fmt.Errorf("repoint during merge: %w", err)
			}
		}

		// Any rows the OR IGNORE left behind belonged to a duplicate that the
		// survivor already had, so deleting them loses nothing.
		for _, stmt := range []string{
			`DELETE FROM device_addresses WHERE device_id = ?`,
			`DELETE FROM device_services  WHERE device_id = ?`,
			`DELETE FROM devices          WHERE id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, stmt, old); err != nil {
				return "", fmt.Errorf("clean up merged device: %w", err)
			}
		}
	}
	return survivor, nil
}

// writeDevice creates or refreshes the device row.
//
// Every discovered field uses COALESCE(NULLIF(...)) so that a source reporting
// nothing cannot erase what another source already established, a neighbour-table
// sighting carries no hostname, and must not blank the one mDNS supplied.
func writeDevice(ctx context.Context, tx *sql.Tx, id string, o types.Sighting) error {
	randomized := o.MAC != "" && discover.IsRandomized(o.MAC)

	_, err := tx.ExecContext(ctx, `
INSERT INTO devices (id, mac, ip, hostname, name, model, vendor, device_type, trust,
                     first_seen, last_seen, online, is_self, mac_randomized)
VALUES (?, ?, ?, ?, ?, ?, ?, '', 'unknown', ?, ?, 1, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  mac            = COALESCE(NULLIF(excluded.mac, ''),      devices.mac),
  ip             = COALESCE(NULLIF(excluded.ip, ''),       devices.ip),
  hostname       = COALESCE(NULLIF(excluded.hostname, ''), devices.hostname),
  name           = COALESCE(NULLIF(excluded.name, ''),     devices.name),
  model          = COALESCE(NULLIF(excluded.model, ''),    devices.model),
  vendor         = COALESCE(NULLIF(excluded.vendor, ''),   devices.vendor),
  first_seen     = MIN(devices.first_seen, excluded.first_seen),
  last_seen      = MAX(devices.last_seen, excluded.last_seen),
  online         = 1,
  is_self        = MAX(devices.is_self, excluded.is_self),
  mac_randomized = excluded.mac_randomized`,
		id, discover.FormatMAC(o.MAC), o.IP, o.Hostname, o.Name, o.Model, o.Vendor,
		o.SeenAt.Unix(), o.SeenAt.Unix(), boolInt(o.IsSelf), boolInt(randomized))
	return err
}

func writeKey(ctx context.Context, tx *sql.Tx, id string, k identityKey, seen time.Time) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO device_keys (key, device_id, kind, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET last_seen = MAX(device_keys.last_seen, excluded.last_seen)`,
		k.String(), id, string(k.Kind), seen.Unix(), seen.Unix())
	return err
}

func writeAddress(ctx context.Context, tx *sql.Tx, id, ip string, seen time.Time) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO device_addresses (device_id, ip, first_seen, last_seen)
VALUES (?, ?, ?, ?)
ON CONFLICT(device_id, ip) DO UPDATE SET last_seen = MAX(device_addresses.last_seen, excluded.last_seen)`,
		id, ip, seen.Unix(), seen.Unix()); err != nil {
		return err
	}
	return adoptPlaceholderFlows(ctx, tx, id, ip)
}

// adoptPlaceholderFlows hands a device the traffic captured before it had a name.
//
// Patrol sees packets, and a packet carries no identity beyond an address, so a
// flow from another machine is tagged `lan-<address>` until discovery says whose
// it is. Nothing used to complete that sentence. The placeholder was written and
// never revisited, so on this network a printer had 2,168 captured flows under
// `lan-192.168.68.58` while its actual Roster entry had none, the same machine
// living as two, with every rule treating them as strangers and its Rap Sheet
// empty. Two of the placeholders were link-local addresses belonging to devices
// already on the Roster, including this one, which had split part of its own
// traffic away from itself.
//
// The moment an address is tied to a device is the moment the placeholder can be
// resolved, so that is where it happens. It is cheap, the placeholder is an
// exact string, and the index on device_id serves the lookup, and it repairs
// history as well as the present.
func adoptPlaceholderFlows(ctx context.Context, tx *sql.Tx, id, ip string) error {
	placeholder := "lan-" + ip
	if id == "" || id == placeholder {
		return nil
	}
	_, err := tx.ExecContext(ctx,
		`UPDATE flows SET device_id = ? WHERE device_id = ?`, id, placeholder)
	return err
}

func writeService(ctx context.Context, tx *sql.Tx, id, svc, source string, seen time.Time) error {
	if svc == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO device_services (device_id, service, source, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(device_id, service) DO UPDATE SET last_seen = MAX(device_services.last_seen, excluded.last_seen)`,
		id, svc, source, seen.Unix(), seen.Unix())
	return err
}

// DeviceAddresses returns every address a device has held, most recent first.
func (s *Store) DeviceAddresses(ctx context.Context, id string) ([]types.DeviceAddress, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ip, first_seen, last_seen FROM device_addresses
WHERE device_id = ? ORDER BY last_seen DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []types.DeviceAddress
	for rows.Next() {
		var (
			a           types.DeviceAddress
			first, last int64
		)
		if err := rows.Scan(&a.IP, &first, &last); err != nil {
			return nil, err
		}
		a.FirstSeen, a.LastSeen = time.Unix(first, 0), time.Unix(last, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeviceServices returns the services a device advertises.
func (s *Store) DeviceServices(ctx context.Context, id string) ([]types.DeviceService, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT service, source, first_seen, last_seen FROM device_services
WHERE device_id = ? ORDER BY service ASC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []types.DeviceService
	for rows.Next() {
		var (
			v           types.DeviceService
			first, last int64
		)
		if err := rows.Scan(&v.Service, &v.Source, &first, &last); err != nil {
			return nil, err
		}
		v.FirstSeen, v.LastSeen = time.Unix(first, 0), time.Unix(last, 0)
		out = append(out, v)
	}
	return out, rows.Err()
}

// OfflineAfter is how long a device may go unseen before the Roster stops
// calling it online.
//
// Comfortably longer than the neighbour poll and than the interval at which
// devices re-announce themselves, so a device is not flickering between states
// because one poll happened to miss it. A phone that genuinely leaves the house
// shows as offline within a few minutes.
const OfflineAfter = 5 * time.Minute

// MarkStaleDevicesOffline clears the online flag on devices nothing has seen
// recently, and reports how many changed.
//
// Without this every device ever seen stays online forever, because a sighting
// can only ever prove presence: nothing announces its own absence.
func (s *Store) MarkStaleDevicesOffline(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE devices SET online = 0 WHERE online = 1 AND last_seen < ?`,
		now.Add(-OfflineAfter).Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RunPresence keeps the online flags honest until ctx is cancelled.
func (s *Store) RunPresence(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.MarkStaleDevicesOffline(ctx, time.Now()); err != nil && ctx.Err() == nil {
				slog.Warn("could not update device presence", "err", err)
			}
		}
	}
}

// RefreshDeviceTypes re-infers what each device is, and returns how many changed.
//
// Runs over the store rather than over individual sightings because the evidence
// arrives from different sources at different times: the neighbour table supplies
// the vendor, mDNS supplies the services, and neither alone is enough. Inference
// needs the merged view, which only exists here.
//
// A type the user set by hand is never overwritten. Discovery is allowed to make
// a first guess, not to keep correcting a person who knows better.
func (s *Store) RefreshDeviceTypes(ctx context.Context, gateway netip.Addr) (int, error) {
	devices, err := s.Devices(ctx)
	if err != nil {
		return 0, err
	}

	changed := 0
	for _, d := range devices {
		if d.TypeLocked {
			continue
		}
		services, err := s.DeviceServices(ctx, d.ID)
		if err != nil {
			return changed, err
		}
		names := make([]string, 0, len(services))
		for _, v := range services {
			names = append(names, v.Service)
		}

		isGateway := gateway.IsValid() && s.deviceHasAddress(ctx, d.ID, gateway.String())
		in := discover.InferType(d, names, isGateway)
		if in.Type == d.DeviceType && in.Because == d.TypeReason {
			continue
		}
		// An inference that found nothing must not erase an earlier one that did:
		// services can be missing from one pass and present in the next.
		if in.Type == "" && d.DeviceType != "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE devices SET device_type = ?, type_reason = ? WHERE id = ?`,
			in.Type, in.Because, d.ID); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

func (s *Store) deviceHasAddress(ctx context.Context, id, ip string) bool {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM device_addresses WHERE device_id = ? AND ip = ?`, id, ip).Scan(&n)
	return err == nil && n > 0
}

// observedServiceWindow is how far back a port sighting still counts as
// evidence that something is listening.
//
// A day, because a service does not stop existing because nobody used it this
// afternoon, but a device reconfigured last month should not keep advertising
// what it used to run. The existing row's last_seen is what ages out; this
// window only bounds the query.
const observedServiceWindow = 24 * time.Hour

// RunDeviceTyping keeps device types and observed services current until ctx is
// cancelled.
func (s *Store) RunDeviceTyping(ctx context.Context, every time.Duration) {
	// The gateway is read once per pass rather than cached for the process
	// lifetime: a laptop moving between networks gets a different one, and a
	// stale gateway would label the wrong device the router.
	run := func() {
		// Services first: a port observed since the last pass may be what
		// identifies the device, and inferring the type before recording it
		// would use evidence one cycle out of date.
		if _, err := s.RefreshObservedServices(ctx, time.Now().Add(-observedServiceWindow)); err != nil && ctx.Err() == nil {
			slog.Warn("could not refresh observed services", "err", err)
		}
		if _, err := s.RefreshDeviceTypes(ctx, discover.DefaultGateway()); err != nil && ctx.Err() == nil {
			slog.Warn("could not refresh device types", "err", err)
		}
	}
	run()

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

// DeviceEdit is what a user may change about a device.
//
// Every field is a pointer so that "not supplied" is distinct from "set to
// empty". Clearing a label is a real instruction and must not be confused with a
// request that simply did not mention it.
type DeviceEdit struct {
	Trust      *string
	Label      *string
	Notes      *string
	DeviceType *string
}

// EditDevice applies a user's changes to a device.
//
// Setting a device type by hand also locks it, because a person correcting a
// wrong guess should not have to keep correcting it every thirty seconds when
// inference runs again. Clearing the type unlocks it and hands the decision back
// to inference.
func (s *Store) EditDevice(ctx context.Context, id string, e DeviceEdit) error {
	sets := []string{}
	args := []any{}

	if e.Trust != nil {
		if !validTrust(*e.Trust) {
			return fmt.Errorf("unknown trust level %q", *e.Trust)
		}
		sets = append(sets, "trust = ?")
		args = append(args, *e.Trust)
	}
	if e.Label != nil {
		sets = append(sets, "label = ?")
		args = append(args, strings.TrimSpace(*e.Label))
	}
	if e.Notes != nil {
		sets = append(sets, "notes = ?")
		args = append(args, strings.TrimSpace(*e.Notes))
	}
	if e.DeviceType != nil {
		t := strings.TrimSpace(*e.DeviceType)
		sets = append(sets, "device_type = ?", "type_locked = ?", "type_reason = ?")
		if t == "" {
			// Handing the decision back to inference, which will fill both
			// columns on its next pass.
			args = append(args, "", 0, "")
		} else {
			args = append(args, t, 1, ReasonManual)
		}
	}

	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)

	res, err := s.db.ExecContext(ctx,
		`UPDATE devices SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

// ReasonManual marks a device type the user chose, as opposed to one inferred.
const ReasonManual = "manual"

// ErrDeviceNotFound is returned when an edit names a device that does not exist.
var ErrDeviceNotFound = errors.New("device not found")

func validTrust(t string) bool {
	switch t {
	case types.TrustUnknown, types.TrustDeputized, types.TrustWatched:
		return true
	}
	return false
}

// RefreshObservedServices records services inferred from the ports that internal
// devices were seen answering on.
//
// This is the passive half of service detection: no scanning, no packets. A
// connection *to* an address on this network reveals that something was
// listening there, and the port conventionally names it.
//
// In Deputy Mode the evidence is limited to what this machine connected to,
// which is real but partial. Patrol Mode sees every device's inbound
// connections. Both feed the same table, distinguished by source, so the UI can
// say how a service was learned.
func (s *Store) RefreshObservedServices(ctx context.Context, since time.Time) (int, error) {
	// Only connections whose destination is a known device on this network, and
	// only ports a service would plausibly live on.
	rows, err := s.db.QueryContext(ctx, `
SELECT a.device_id, f.dst_port, f.proto, MIN(f.ts_start), MAX(f.ts_last)
FROM flows f
JOIN device_addresses a ON a.ip = f.dst_ip
-- Only connections that actually came up. A refused or still-connecting socket
-- is not evidence that anything is listening, and the on-demand port check
-- produces those by design: without this filter, checking a device taught the
-- Roster that it offers every port we knocked on.
WHERE f.ts_last >= ? AND f.dst_port > 0 AND f.established = 1
GROUP BY a.device_id, f.dst_port, f.proto`, since.Unix())
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type observed struct {
		deviceID    string
		service     string
		first, last int64
	}
	var found []observed
	for rows.Next() {
		var (
			deviceID, proto string
			port            int
			first, last     int64
		)
		if err := rows.Scan(&deviceID, &port, &proto, &first, &last); err != nil {
			return 0, err
		}
		if port < 0 || port > 65535 || !discover.PortIsInteresting(uint16(port)) {
			continue
		}
		name := discover.ServiceForPort(uint16(port), proto)
		if name == "" {
			continue
		}
		found = append(found, observed{deviceID, name, first, last})
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, o := range found {
		if _, err := s.db.ExecContext(ctx, `
INSERT INTO device_services (device_id, service, source, first_seen, last_seen)
VALUES (?, ?, 'observed', ?, ?)
ON CONFLICT(device_id, service) DO UPDATE SET
  last_seen = MAX(device_services.last_seen, excluded.last_seen)`,
			o.deviceID, o.service, o.first, o.last); err != nil {
			return 0, err
		}
	}
	return len(found), nil
}

// RecordScannedServices stores the result of a user-requested port check.
//
// Recorded with source "scan" so the Roster can say how a service was learned,
// a device that advertised SSH and a device that merely answered on 22 are
// different claims, and the second is the weaker one.
func (s *Store) RecordScannedServices(ctx context.Context, id string, open []discover.OpenPort) error {
	now := time.Now().Unix()
	for _, p := range open {
		name := p.Service
		if name == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `
INSERT INTO device_services (device_id, service, source, first_seen, last_seen)
VALUES (?, ?, 'scan', ?, ?)
ON CONFLICT(device_id, service) DO UPDATE SET
  last_seen = MAX(device_services.last_seen, excluded.last_seen)`,
			id, name, now, now); err != nil {
			return err
		}
	}
	return nil
}
