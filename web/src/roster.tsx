import { useCallback, useEffect, useMemo, useState } from 'preact/hooks'
import {
  fetchDevices, editDevice, scanDevice, displayName, fmtAgo,
  DEVICE_TYPES, TRUST_DEPUTIZED, TRUST_WATCHED, TRUST_UNKNOWN,
  fetchDispatch, fingerprint, fetchPeerDevices, fmtBytes,
  type Device, type RosterData, type PeerState, type PeerDevice,
} from './api'
import { useI18n, fill } from './i18n'
import { Freshness, usePolling } from './freshness'

/**
 * The Roster: what is on this network.
 *
 * Deliberately a table rather than a card grid. People come here to find one
 * device among many, and scanning a column is faster than scanning tiles. The
 * detail panel opens beside it rather than navigating away, so the list stays
 * on screen while you look.
 */
/** How often the Roster re-reads the device list. */
const REFRESH_MS = 10000

/**
 * Matches paired peers to the devices they are.
 *
 * A peer is a machine on this network, so discovery has almost certainly found
 * it already, it has a MAC, an address and a name like anything else. Listing
 * it a second time as a "peer" would show one machine twice and invite the user
 * to wonder which is which.
 *
 * So a peer is not a new row. It is a badge on the row that is already there,
 * matched by the address we dial it at. A peer we cannot match, on another
 * subnet, or not yet discovered, is counted separately rather than dropped,
 * because silently showing fewer peers than are paired would be worse than
 * saying so.
 */
function peersByAddress(peers: PeerState[]): Map<string, PeerState> {
  const byIP = new Map<string, PeerState>()
  for (const p of peers) {
    if (!p.addr) continue
    // Strip the port; IPv6 addresses are bracketed, so take the last colon.
    const host = p.addr.startsWith('[')
      ? p.addr.slice(1, p.addr.indexOf(']'))
      : p.addr.slice(0, p.addr.lastIndexOf(':'))
    if (host) byIP.set(host, p)
  }
  return byIP
}

export function Roster({ layer = '', openDevice }: { layer?: string; openDevice?: string }) {
  const { t } = useI18n()
  const [data, setData] = useState<RosterData | null>(null)
  const [peers, setPeers] = useState<PeerState[]>([])

  // **Devices belonging to paired machines.**
  //
  // Their own section rather than more rows in the list above, because a peer
  // sends a name and some counts and nothing else the Roster is built to show.
  // Mixed in, they would be rows with an empty maker, no addresses and no
  // services, which reads as a lookup that failed rather than as detail that
  // was never transmitted.
  const [peerDevices, setPeerDevices] = useState<PeerDevice[]>([])
  useEffect(() => {
    if (layer === '') { setPeerDevices([]); return }
    let cancelled = false
    fetchPeerDevices(layer)
      .then((d) => { if (!cancelled) setPeerDevices(d.devices ?? []) })
      .catch(() => { if (!cancelled) setPeerDevices([]) })
    return () => { cancelled = true }
  }, [layer])

  // Loaded once: peering is enabled by a command-line flag, so it cannot start
  // or stop while the page is open.
  useEffect(() => {
    let cancelled = false
    fetchDispatch()
      .then((d) => { if (!cancelled) setPeers(d.enabled ? d.peers : []) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [])
  const [query, setQuery] = useState('')
  const [showOffline, setShowOffline] = useState(true)
  const [selected, setSelected] = useState<string | null>(openDevice ?? null)

  // Arriving from somewhere that already knows which device is meant.
  //
  // The Wanted List and the Right Now panel both offer a device by name and
  // then switched to this page without it: the reader had pointed at the one
  // row they cared about, and was handed the whole list to find it in again.
  // Worse on a network with fifty devices, which is the case where something
  // being on the Wanted List matters most.
  useEffect(() => {
    if (openDevice) setSelected(openDevice)
  }, [openDevice])

  // Throws on failure rather than swallowing, so the freshness indicator can
  // tell a stale view from a fresh one instead of reporting "updated just now"
  // after a request that never landed.
  const load = useCallback(async () => {
    setData(await fetchDevices())
  }, [])

  const { updatedAt, busy, refresh } = usePolling(load, REFRESH_MS)

  const devices = useMemo(() => {
    const all = data?.devices ?? []
    const q = query.trim().toLowerCase()
    return all
      .filter((d) => showOffline || d.online)
      .filter((d) => !q || searchText(d).includes(q))
      .sort(byPresenceThenName)
  }, [data, query, showOffline])

  const chosen = devices.find((d) => d.id === selected) ?? null
  const gateway = data?.discovery.gateway ?? ''

  // A device may hold several addresses over time, so every one is checked
  // rather than only the current lease.
  const peerIndex = useMemo(() => peersByAddress(peers), [peers])
  // **Current address only.**
  //
  // This used to check a device's whole address history as well, on the
  // reasoning that a machine holds several addresses over time and any of them
  // might be the one we dial. The opposite is true: a router hands the same
  // address to different machines over the weeks, so every device that has ever
  // held the peer's current address gets badged as that peer. Seen with three
  // at once, an Xbox that had been offline for days, this Mac, and the peer
  // itself, all claiming 192.168.68.56 in their histories.
  //
  // A peer is reachable at exactly one address right now, which is the one it is
  // dialled at, so that is the only one that can identify it. A peer whose
  // address matches nothing current is counted as unmatched below and said out
  // loud rather than pinned to whichever device used to hold it.
  const peerFor = (d: Device): PeerState | undefined => {
    if (d.ip && peerIndex.has(d.ip)) return peerIndex.get(d.ip)
    return undefined
  }

  // Paired peers that no row accounts for: on another subnet, or not yet
  // discovered. Said rather than silently omitted.
  const unmatchedPeers = peers.filter(
    (p) => !(data?.devices ?? []).some((d) => peerFor(d)?.peer_id === p.peer_id),
  ).length

  // Same reasoning as Radio Chatter: until the first fetch lands, "no devices"
  // and "not loaded yet" are indistinguishable, and showing the empty-state
  // explanation for one frame reads as a broken view.
  if (!data) return <div class="chatter-loading" aria-busy="true" />

  // Defensive as well as fixed at the source. The server no longer sends null
  // here, and a client that throws on an unexpected null still shows a blank
  // screen the user can neither act on nor report usefully.
  const found = data.devices ?? []
  if (found.length === 0) {
    return (
      <div class="stub">
        <h2>{t.roster.title}</h2>
        <p>{t.roster.empty}</p>
        <span class="milestone">{t.roster.emptyHint}</span>
      </div>
    )
  }

  const peerSection = peerDevices.length > 0 && (
    <section class="roster-peers panel">
      <h3>{t.roster.peerHead}</h3>
      <p class="roster-peers-note">{fill(t.roster.peerNote, { n: peerDevices.length })}</p>
      <ul>
        {peerDevices.map((d) => (
          <li key={d.id}>
            <div class="rp-top">
              <span class="rp-name">{d.device}</span>
              <span class="chip device">{d.label}</span>
            </div>
            <div class="rp-sub">
              {d.top_org && <>{d.top_org}{' · '}</>}
              {fill(d.orgs === 1 ? t.roster.peerOrgs : t.roster.peerOrgsPlural, { n: d.orgs })}
              {' · '}
              {fill(d.flows === 1 ? t.watchtower.connections : t.watchtower.connectionsPlural,
                    { count: d.flows })}
              {d.bytes > 0 && <>{' · '}{fmtBytes(d.bytes)}</>}
            </div>
            {d.top_app && <div class="rp-apps"><span class="chip">{d.top_app}</span></div>}
          </li>
        ))}
      </ul>
    </section>
  )

  return (
    <div class="roster">
      <div class="roster-head panel">
        <input
          class="roster-search"
          type="search"
          value={query}
          placeholder={t.roster.searchPlaceholder}
          onInput={(e) => setQuery((e.target as HTMLInputElement).value)}
        />
        <span class="roster-count">
          {devices.length} {t.roster.devices}
          {/* Peers that no row accounts for, on another subnet, or not yet
              discovered. Shown rather than silently omitted: a peer list that
              is shorter than the number paired is a lie by subtraction. */}
          {unmatchedPeers > 0 && (
            <span class="roster-elsewhere">
              {' · '}{fill(t.roster.pairedElsewhere, { count: unmatchedPeers })}
            </span>
          )}
        </span>
        <label class="chatter-toggle">
          <input
            type="checkbox"
            checked={showOffline}
            onChange={(e) => setShowOffline((e.target as HTMLInputElement).checked)}
          />
          {t.roster.showOffline}
        </label>
        <Freshness
          updatedAt={updatedAt}
          intervalMs={REFRESH_MS}
          busy={busy}
          onRefresh={refresh}
        />
      </div>

      <div class={`roster-body ${chosen ? '' : 'solo'}`}>
        <div class="roster-list panel">
          <table class="roster-table">
            <thead>
              <tr>
                <th>{t.roster.colDevice}</th>
                <th>{t.roster.colType}</th>
                <th>{t.roster.colAddress}</th>
                <th>{t.roster.colVendor}</th>
                <th>{t.roster.colLastSeen}</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr
                  key={d.id}
                  class={`${d.id === selected ? 'on' : ''} ${d.online ? '' : 'off'}`}
                  onClick={() => setSelected(d.id === selected ? null : d.id)}
                >
                  <td>
                    <span class={`presence ${d.online ? 'up' : 'down'}`} title={d.online ? t.roster.online : t.roster.offline} />
                    <b>{displayName(d)}</b>
                    {d.is_self && <span class="tag self">{t.roster.thisMachine}</span>}
                    {peerFor(d) && (
                      <span
                        class={`tag peer ${peerFor(d)!.status}`}
                        title={fingerprint(peerFor(d)!.peer_id)}
                      >
                        {t.roster.pairedPeer}
                      </span>
                    )}
                    {gateway && d.ip === gateway && !d.is_self && (
                      <span class="tag gw">{t.roster.gateway}</span>
                    )}
                  </td>
                  <td>
                    {typeLabel(t, d.device_type)}
                    {d.trust === TRUST_DEPUTIZED && <span class="tag deputized">{t.deputize.deputized}</span>}
                    {d.trust === TRUST_WATCHED && <span class="tag watched">{t.deputize.watched}</span>}
                  </td>
                  {/* A placeholder, not a comma. These two cells read '—' until
                      the em dash purge rewrote every one in the tree, and a
                      dash in a table cell is not the prose punctuation that rule
                      is about: the result was a column of bare commas under the
                      heading "Maker". A middle dot instead, the same character
                      the status bar uses for a value it does not have yet. */}
                  <td class="mono"><bdi>{d.ip || '\u00b7'}</bdi></td>
                  <td><bdi>{d.vendor || '\u00b7'}</bdi></td>
                  <td>{d.online ? t.roster.online : fmtAgo(d.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {chosen && <Detail device={chosen} onClose={() => setSelected(null)} onSaved={refresh} />}
      </div>

      {peerSection}
    </div>
  )
}

function Detail({
  device, onClose, onSaved,
}: {
  device: Device
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useI18n()
  const services = device.services ?? []
  const addresses = device.addresses ?? []

  // Local copies so typing is not fought by the ten-second refresh. Keyed on the
  // device id so switching selection loads the new device rather than carrying
  // the previous one's half-typed label across.
  const [label, setLabel] = useState(device.label ?? '')
  const [notes, setNotes] = useState(device.notes ?? '')
  const [status, setStatus] = useState<'' | 'saved' | 'failed'>('')
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<string>('')

  useEffect(() => {
    setLabel(device.label ?? '')
    setNotes(device.notes ?? '')
    setStatus('')
    setScanResult('')
  }, [device.id])

  const check = async () => {
    setScanning(true)
    setScanResult('')
    try {
      const res = await scanDevice(device.id)
      setScanResult(fill(t.scan.checkedResult, {
        open: String(res.open.length),
        checked: String(res.checked),
      }))
      onSaved()
    } catch (e) {
      // The server already says something useful here: "this device has no
      // usable address", "only devices on this network can be checked". All of
      // it was being thrown away and replaced with "Could not save", which is
      // the message for editing a device and describes something this button
      // does not do. A tester saw it beside Check ports and had no way to know
      // whether the scan failed, the save failed, or what to do next.
      setScanResult((e as Error).message || t.scan.checkFailed)
    } finally {
      setScanning(false)
    }
  }

  const apply = async (patch: Parameters<typeof editDevice>[1]) => {
    try {
      await editDevice(device.id, patch)
      setStatus('saved')
      onSaved()
    } catch {
      setStatus('failed')
    }
  }

  return (
    <aside class="roster-detail panel">
      <div class="detail-head">
        <h3>{displayName(device)}</h3>
        <button class="icon-btn" title={t.roster.close} onClick={onClose}>×</button>
      </div>

      {device.device_type && (
        <p class="detail-why">
          {fill(t.roster.identifiedBy, {
            type: typeLabel(t, device.device_type),
            evidence: evidenceLabel(t, device.type_reason),
          })}
        </p>
      )}

      <div class="trust-row">
        {[
          { code: TRUST_DEPUTIZED, label: t.deputize.deputize },
          { code: TRUST_WATCHED, label: t.deputize.watch },
          { code: TRUST_UNKNOWN, label: t.deputize.clear },
        ].map((b) => (
          <button
            key={b.code}
            class={`range ${device.trust === b.code ? 'on' : ''}`}
            title={t.deputize.trustHelp}
            onClick={() => apply({ trust: b.code })}
          >
            {b.label}
          </button>
        ))}
      </div>

      <div class="detail-edit">
        <label>
          {t.deputize.label}
          <input
            type="text"
            value={label}
            placeholder={t.deputize.labelPlaceholder}
            onInput={(e) => setLabel((e.target as HTMLInputElement).value)}
            onBlur={() => label !== (device.label ?? '') && apply({ label })}
          />
        </label>

        <label>
          {t.deputize.type}
          <select
            value={device.type_locked ? (device.device_type ?? '') : ''}
            title={t.deputize.typeHelp}
            onChange={(e) => apply({ device_type: (e.target as HTMLSelectElement).value })}
          >
            <option value="">{t.deputize.typeAuto}</option>
            {DEVICE_TYPES.map((code) => (
              <option key={code} value={code}>{typeLabel(t, code)}</option>
            ))}
          </select>
        </label>

        <label>
          {t.deputize.notes}
          <textarea
            rows={2}
            value={notes}
            placeholder={t.deputize.notesPlaceholder}
            onInput={(e) => setNotes((e.target as HTMLTextAreaElement).value)}
            onBlur={() => notes !== (device.notes ?? '') && apply({ notes })}
          />
        </label>

        {status && (
          <span class={status === 'saved' ? 'muted' : 'save-failed'}>
            {status === 'saved' ? t.deputize.saved : t.deputize.saveFailed}
          </span>
        )}
      </div>

      <dl class="detail-list">
        {device.mac && (
          <>
            <dt>{t.roster.hardwareAddress}</dt>
            <dd>
              <span class="mono">{device.mac}</span>
              {device.mac_randomized && (
                <span class="tag" title={t.roster.randomizedHelp}>{t.roster.randomized}</span>
              )}
            </dd>
          </>
        )}
        {device.hostname && (<><dt>{t.roster.hostname}</dt><dd>{device.hostname}</dd></>)}
        {device.model && (<><dt>{t.roster.model}</dt><dd>{device.model}</dd></>)}
        {device.vendor && (<><dt>{t.roster.colVendor}</dt><dd>{device.vendor}</dd></>)}

        <dt>{t.roster.addresses}</dt>
        <dd>
          {addresses.length === 0
            ? (device.ip || '\u00b7')
            : addresses.map((a) => <div class="mono" key={a.ip}>{a.ip}</div>)}
        </dd>

        <dt>{t.roster.services}</dt>
        <dd>
          {services.length === 0
            ? <span class="muted">{t.roster.noServices}</span>
            : <div class="svc-tags">
                {services.map((s) => (
                  <span class={`tag svc ${s.source}`} key={s.service} title={sourceLabel(t, s.source)}>
                    {s.service}
                  </span>
                ))}
              </div>}
          {/* The one deliberate act in the product. Behind a button, never
              scheduled, and it says what it will do before it does it. */}
          {!device.is_self && (
            <div class="scan-row">
              <button class="range" disabled={scanning} onClick={check} title={t.scan.checkHelp}>
                {scanning ? t.scan.checking : t.scan.checkPorts}
              </button>
              {scanResult && <span class="muted">{scanResult}</span>}
            </div>
          )}
        </dd>

        <dt>{t.roster.firstSeen}</dt>
        <dd>{fmtAgo(device.first_seen)}</dd>
        <dt>{t.roster.colLastSeen}</dt>
        <dd>{device.online ? t.roster.online : fmtAgo(device.last_seen)}</dd>
      </dl>
    </aside>
  )
}

/**
 * typeLabel translates a device type code.
 *
 * The backend stores a stable code precisely so this can happen here: an English
 * phrase written into the database would be untranslatable afterwards. An
 * unrecognized code falls back to "unknown" rather than showing the raw value.
 */
function typeLabel(t: any, code?: string): string {
  if (!code) return t.deviceType.unknown
  return t.deviceType[code] ?? t.deviceType.unknown
}

function evidenceLabel(t: any, code?: string): string {
  if (!code) return ''
  return t.evidence[code] ?? ''
}

/** searchText is everything about a device worth matching a query against. */
function searchText(d: Device): string {
  return [
    d.label, d.name, d.hostname, d.model, d.vendor, d.ip, d.mac,
    ...(d.services ?? []).map((s) => s.service),
    ...(d.addresses ?? []).map((a) => a.ip),
  ].filter(Boolean).join(' ').toLowerCase()
}

/**
 * byPresenceThenName orders the list so it stays readable as devices come and go.
 *
 * This machine first because it is the one the user is certain about, then
 * everything online, then by name. Sorting by last-seen instead would reshuffle
 * the table under the cursor every few seconds.
 */
function byPresenceThenName(a: Device, b: Device): number {
  if (a.is_self !== b.is_self) return a.is_self ? -1 : 1
  if (a.online !== b.online) return a.online ? -1 : 1
  return displayName(a).localeCompare(displayName(b))
}

/** sourceLabel says how a service was learned, since the claims differ in
 *  strength: a device that advertised SSH and one that merely answered on 22 are
 *  not making the same statement. */
function sourceLabel(t: any, source: string): string {
  switch (source) {
    case 'scan': return t.scan.sourceScan
    case 'observed': return t.scan.sourceObserved
    default: return t.scan.sourceAdvertised
  }
}
