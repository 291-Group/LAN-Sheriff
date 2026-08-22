// The single place that knows how to talk to the backend. Every view reads
// from here; nothing keeps its own copy of application state in localStorage.

export interface Origin {
  lat: number
  lon: number
  label: string
  country?: string
  city?: string
  known: boolean
}

export interface Endpoint {
  ip: string
  rdns?: string
  asn?: number
  org?: string
  country?: string
  country_name?: string
  city?: string
  lat?: number
  lon?: number
  is_internal: boolean
  first_seen: string
  last_seen: string
  conns: number
  bytes_out: number
  bytes_in: number
  processes?: string[]
  devices?: string[]
  ports?: number[]
  active: boolean
  last_flow: number
}

/** Resolves a backend message code to translated text.
 *
 *  The server cannot know the viewer's language, so anything meant for a person
 *  arrives as a stable code with English prose beside it. The code is preferred;
 *  the prose is the fallback for a code this build does not recognize yet. */
export function message(
  msgs: Record<string, string>,
  code: string | undefined,
  fallback?: string,
): string {
  if (code && msgs[code]) return msgs[code]
  return fallback ?? ''
}

export interface Capabilities {
  mode: string
  available: boolean
  host_egress: boolean
  other_devices: boolean
  process_attribution: boolean
  byte_counts: boolean
  dns_feed: boolean
  device_inventory: boolean
  topology: string
  hint?: string
  hint_code?: string
  enable_cmd?: string
}

export interface Count { key: string; label?: string; n: number }

export interface AuthStatus {
  required: boolean
  needs_setup: boolean
  authenticated: boolean
  locked_out: boolean
  exposed: boolean
  min_password_len: number
  /** Shown on the sign-in screen, which is the only view available before
   *  anybody can reach the dashboard's own footer. */
  version?: string
  build?: string
}

export const fetchAuthStatus = () => get<AuthStatus>('/api/auth/status')

export async function logout(): Promise<void> {
  await fetch('/api/auth/logout', { method: 'POST' })
}

export interface Summary {
  flows: number
  active_flows: number
  endpoints: number
  countries: number
  devices: number
  dns_events: number
  top_orgs: Count[] | null
  top_countries: Count[] | null
  top_processes: Count[] | null
  db_bytes: number
  mode: string
  capabilities: Capabilities
  origin: Origin
  version: string
  build: string
  host: string
  notes?: string[]
  note_codes?: string[]
}

/** The filter every view shares. Empty fields mean "no constraint". */
export interface Filter {
  range: string
  device?: string
  process?: string
  country?: string
  org?: string
  proto?: string
  port?: number
  q?: string
  /** Explicit window in unix seconds, set by the scrub control. Overrides range. */
  from?: number
  to?: number
}

export const emptyFilter: Filter = { range: '24h' }

/** Serialises a filter into query parameters. */
export function filterQuery(f: Filter, extra: Record<string, string | number> = {}): string {
  const p = new URLSearchParams()
  if (f.from) {
    p.set('from', String(f.from))
    if (f.to) p.set('to', String(f.to))
  } else {
    p.set('range', f.range)
  }
  for (const k of ['device', 'process', 'country', 'org', 'proto', 'q'] as const) {
    const v = f[k]
    if (v) p.set(k, String(v))
  }
  if (f.port) p.set('port', String(f.port))
  for (const [k, v] of Object.entries(extra)) p.set(k, String(v))
  return p.toString()
}

/** True when anything is narrowing the view. */
export function filterIsActive(f: Filter): boolean {
  return Boolean(f.device || f.process || f.country || f.org || f.proto || f.port || f.q)
}

export interface TimePoint {
  ts: number
  conns: number
  bytes_out: number
  bytes_in: number
  endpoints: number
}

export interface SearchResult {
  /** The machine that reported this hit; empty for anything seen here. */
  peer?: string
  kind: 'endpoint' | 'org' | 'process' | 'country'
  key: string
  label: string
  detail?: string
  count: number
}

export interface SettingsData {
  retention_raw_hours: number
  retention_rollup_days: number
  storage_max_mb: number
  db_bytes: number
  data_dir: string
}

/**
 * The session ended while the page was open.
 *
 * Worth a type of its own rather than a status code buried in a message,
 * because it is the one failure that is not the caller's problem to handle: no
 * amount of retrying a widget's poll will fix it, and the only useful response
 * is at the top of the tree, which is where `notifyUnauthorized` sends it.
 */
export class Unauthorized extends Error {
  constructor(path: string) {
    super(`${path}: 401`)
    this.name = 'Unauthorized'
  }
}

let unauthorizedHandler: () => void = () => {}

/**
 * Register what to do when the server stops recognising this session.
 *
 * # Why this needs to exist at all
 *
 * Sessions live in a map in memory (see internal/auth), so every restart of
 * LAN Sheriff invalidates every one of them. That is a reasonable thing for a
 * security tool to do, but it means "the session went away underneath an open
 * page" is not an edge case: it is what happens on every update, every reboot,
 * and every crash, to every tab anyone left open.
 *
 * Before this, the dashboard checked authentication exactly once, when it
 * mounted. Afterwards, every poll that came back 401 was swallowed by a
 * `.catch(() => {})`, so the page carried on showing the last data it had
 * managed to fetch, indefinitely, with nothing to say it had stopped. A
 * network monitor frozen on old data does not look broken. It looks quiet,
 * which is the most dangerous thing it could possibly look.
 */
export function setUnauthorizedHandler(fn: () => void) {
  unauthorizedHandler = fn
}

/** Shared by both helpers below: 401 is signalled upwards, then thrown. */
function raiseIfUnauthorized(res: Response, path: string) {
  if (res.status !== 401) return
  unauthorizedHandler()
  throw new Unauthorized(path)
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: 'application/json' } })
  raiseIfUnauthorized(res, path)
  if (!res.ok) throw new Error(`${path}: ${res.status}`)
  return res.json() as Promise<T>
}

export const fetchSummary = (f: Filter) =>
  get<Summary>(`/api/summary?${filterQuery(f)}`)

export const fetchEgress = (f: Filter) =>
  get<{ origin: Origin; endpoints: Endpoint[]; truncated: number }>(
    `/api/egress?${filterQuery(f, { limit: 600 })}`)

export const fetchInbound = (f: Filter) =>
  get<{ endpoints: Endpoint[] }>(`/api/inbound?${filterQuery(f, { limit: 200 })}`)

export const fetchTimeline = (f: Filter) =>
  get<{ from: number; to: number; points: TimePoint[] }>(`/api/timeline?${filterQuery(f)}`)

export const search = (term: string, layer = '') =>
  get<{ results: SearchResult[] }>(
    `/api/search?q=${encodeURIComponent(term)}` +
    (layer ? `&layer=${encodeURIComponent(layer)}&range=24h` : ''))

export interface DNSEvent {
  id: number
  ts: string
  device_id?: string
  process?: string
  qname: string
  qtype?: string
  answers?: string[]
  resp_ms?: number
  flagged?: string
}

export interface DomainSummary {
  domain: string
  lookups: number
  devices: number
  first_seen: number
  last_seen: number
  flagged?: string
  new: boolean
}

export interface DNSSummary {
  capable: boolean
  hint?: string
  hint_code?: string
  labelled_domains?: number
  stats: {
    lookups: number
    domains: number
    new_domains: number
    flagged: number
    devices: number
  }
}

export const fetchDNS = (f: Filter, flaggedOnly = false) =>
  get<{ events: DNSEvent[]; capable: boolean }>(
    `/api/dns?${filterQuery(f, flaggedOnly ? { flagged: 1, limit: 300 } : { limit: 300 })}`)

export const fetchDNSSummary = (f: Filter) =>
  get<DNSSummary>(`/api/dns/summary?${filterQuery(f)}`)

export const fetchTopDomains = (f: Filter) =>
  get<{ domains: DomainSummary[] }>(`/api/dns/domains?${filterQuery(f, { limit: 40 })}`)

export const fetchNewDomains = (f: Filter) =>
  get<{ domains: DomainSummary[] }>(`/api/dns/new?${filterQuery(f, { limit: 60 })}`)

export const fetchSettings = () => get<SettingsData>('/api/settings')

export async function saveSettings(s: SettingsData): Promise<SettingsData> {
  const res = await fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(s),
  })
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'could not save')
  return res.json()
}

export async function wipeData(): Promise<void> {
  const res = await fetch('/api/wipe', { method: 'POST' })
  if (!res.ok) throw new Error('could not wipe')
}

/** Builds an export URL; the browser downloads it directly. */
export function exportUrl(f: Filter, view: string, format: string): string {
  return `/api/export?${filterQuery(f, { view, format })}`
}

export type StreamEvent =
  | { type: 'status'; data: { connected: boolean; mode: string; origin: Origin } }
  | { type: 'flow'; data: { phase: string; flow: Flow } }
  | { type: 'dns'; data: unknown }
  | { type: 'device'; data: unknown }

export interface Flow {
  ts_start: string
  ts_last: string
  device_id?: string
  process?: string
  pid?: number
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  proto: string
  bytes_out: number
  bytes_in: number
  direction: 'out' | 'in' | 'internal'
  active: boolean
}

/**
 * Connects to the live feed, reconnecting with backoff. Returns a teardown
 * function. The socket is the source of liveness for the whole UI: if it drops,
 * every view should say so rather than quietly showing stale data.
 */
export function connectStream(
  onEvent: (ev: StreamEvent) => void,
  onOpen: () => void,
  onClose: () => void,
): () => void {
  let ws: WebSocket | null = null
  let closed = false
  let retry = 0
  let timer: number | undefined

  const open = () => {
    if (closed) return
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    ws = new WebSocket(`${proto}//${location.host}/api/stream`)

    ws.onopen = () => {
      retry = 0
      onOpen()
    }
    ws.onmessage = (m) => {
      try {
        onEvent(JSON.parse(m.data) as StreamEvent)
      } catch {
        /* a malformed frame is not worth tearing the socket down for */
      }
    }
    ws.onclose = () => {
      onClose()
      if (closed) return
      // Back off to a ceiling of 10s so a stopped backend does not turn into a
      // reconnect storm.
      const wait = Math.min(10000, 500 * 2 ** retry++)
      timer = window.setTimeout(open, wait)
    }
    ws.onerror = () => ws?.close()
  }

  open()
  return () => {
    closed = true
    if (timer) clearTimeout(timer)
    ws?.close()
  }
}

// ---------- formatting ----------

export function fmtBytes(n: number): string {
  if (!n) return '\u00b7'   // a placeholder; the em dash purge briefly made this a comma
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++ }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`
}

/**
 * The language relative times are written in.
 *
 * Held here rather than passed to every call because fmtAgo has ten call sites
 * across six components, and threading a catalogue through all of them to
 * format "5 min ago" is a lot of argument for one string. The i18n provider
 * sets this when the language changes.
 */
let timeLocale = 'en'
let rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'short' })

export function setTimeLocale(lang: string): void {
  if (lang === timeLocale) return
  timeLocale = lang
  rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto', style: 'short' })
}

/**
 * How long ago, in the reader's language.
 *
 * This was five hardcoded English strings, so every timestamp in the product
 * read "just now" and "4 d ago" in all twelve languages: the Roster's last-seen
 * column, every row of Radio Chatter, every finding on the Wanted List and the
 * peer list in The Dispatch. A dashboard translated everywhere except the one
 * column that changes every second is not a translated dashboard.
 *
 * Intl rather than a catalogue, because the catalogue would need a plural form
 * per language and this needs none: Intl.RelativeTimeFormat already carries the
 * rules for Arabic's six plural categories and Russian's three, and gets them
 * right without anybody maintaining them. `numeric: 'auto'` is what turns zero
 * into "now" and "الآن" rather than "in 0 seconds".
 *
 * The formatter is rebuilt only when the language changes; constructing one per
 * row is measurably slow and this runs once per visible row per refresh.
 *
 * `style: 'short'` because this is a column, not a sentence. The long form is
 * "10 minutes ago" where the code it replaced said "10 min ago", and the extra
 * word wrapped every row of Radio Chatter onto two lines. Short gives "10 min.
 * ago", and each language its own abbreviation: "vor 10 Min.", "10 мин. назад",
 * "hace 10 min". The languages with no shorter form, Japanese and Chinese among
 * them, simply return the same string, which is the right answer rather than a
 * missing one.
 */
export function fmtAgo(iso: string | number): string {
  const t = typeof iso === 'number' ? iso * 1000 : Date.parse(iso)
  const s = Math.max(0, (Date.now() - t) / 1000)
  if (s < 45) return rtf.format(0, 'second')
  if (s < 3600) return rtf.format(-Math.max(1, Math.round(s / 60)), 'minute')
  if (s < 86400) return rtf.format(-Math.round(s / 3600), 'hour')
  return rtf.format(-Math.round(s / 86400), 'day')
}

/** ISO 3166-1 alpha-2 to the regional-indicator flag emoji. */
export function flag(cc?: string): string {
  if (!cc || cc.length !== 2) return ''
  const base = 0x1f1e6
  return String.fromCodePoint(
    base + cc.toUpperCase().charCodeAt(0) - 65,
    base + cc.toUpperCase().charCodeAt(1) - 65,
  )
}

/** A short label for an endpoint: the organization if we know it, else rDNS, else the IP. */
export function endpointLabel(e: Endpoint): string {
  return e.org || e.rdns || e.ip
}

export interface DeviceAddress {
  ip: string
  first_seen: string
  last_seen: string
}

export interface DeviceService {
  service: string
  source: string
  first_seen: string
  last_seen: string
}

export interface Device {
  id: string
  mac?: string
  ip?: string
  hostname?: string
  /** What the device calls itself. */
  name?: string
  /** What the user called it, which always wins for display. */
  label?: string
  model?: string
  vendor?: string
  device_type?: string
  /** Stable code naming the evidence behind device_type. */
  type_reason?: string
  type_locked?: boolean
  trust: string
  first_seen: string
  last_seen: string
  online: boolean
  is_self: boolean
  mac_randomized?: boolean
  addresses?: DeviceAddress[]
  services?: DeviceService[]
  notes?: string
}

export interface RosterData {
  devices: Device[]
  discovery: { gateway: string }
}

export const fetchDevices = () => get<RosterData>('/api/devices')

export interface IngestHealth {
  writes: number
  failures: number
  consecutive_failures: number
  last_error?: string
  last_failure?: string
  last_write?: string
}

export const fetchHealth = () =>
  get<{ tracked: boolean; ingest?: IngestHealth }>('/api/health')

/**
 * displayName picks what to call a device.
 *
 * A name the user chose always wins. After that, what the device published about
 * itself beats a hostname, which beats a model. Falling all the way through to
 * the address is honest rather than inventing something.
 */
export function displayName(d: Device): string {
  return d.label || d.name || d.hostname || d.model || d.ip || d.mac || ''
}

/**
 * DeviceEdit carries only what the user changed.
 *
 * Every field is optional so that an omitted one is left alone while an empty
 * string clears it. Saving a note must not silently reset a trust level.
 */
export interface DeviceEdit {
  trust?: string
  label?: string
  notes?: string
  device_type?: string
}

export async function editDevice(id: string, patch: DeviceEdit): Promise<void> {
  const res = await fetch(`/api/devices/${encodeURIComponent(id)}/trust`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  })
  if (!res.ok) {
    throw new Error((await res.json().catch(() => ({}))).error || 'could not save')
  }
}

/** Trust levels, matching the backend's stable codes. */
export const TRUST_UNKNOWN = 'unknown'
export const TRUST_DEPUTIZED = 'deputized'
export const TRUST_WATCHED = 'watched'

/** Device type codes the user may choose from when correcting a guess. */
export const DEVICE_TYPES = [
  'router', 'printer', 'tv', 'speaker', 'phone', 'tablet', 'computer',
  'single-board-computer', 'nas', 'camera', 'games-console', 'smart-home',
] as const

export interface TopoNode {
  id: string
  /** "device" for something on this network, "org" for a destination, "gateway" for the router. */
  /** "peer_device" is a device on a paired machine's network: neither one of
   *  ours nor a destination, and never merged with a local device, because two
   *  households can each own a laptop of the same name. */
  kind: 'device' | 'org' | 'gateway' | 'peer_device'
  label: string
  type?: string
  country?: string
  conns: number
  bytes: number
  online?: boolean
  trust?: string
  /** True for an organization this network had not contacted before the window. */
  new?: boolean
}

export interface TopoEdge {
  source: string
  target: string
  conns: number
  bytes: number
}

export interface Topology {
  nodes: TopoNode[]
  edges: TopoEdge[]
  /** How many quieter organizations were folded away to keep the graph readable. */
  truncated: number
}

export const fetchTopology = (f: Filter, layer = '') =>
  get<Topology>(`/api/topology?${filterQuery(f, layer ? { layer } : {})}`)

export interface GlanceData {
  new_orgs: number
  new_devices: number
  loudest_device?: string
  loudest_id?: string
  loudest_conns?: number
  /** Hour of the local day, or -1 when there is not enough history to say. */
  quietest_hour: number
  quietest_conns: number
  devices_online: number
  devices_known: number
  window: string
}

export const fetchGlance = () =>
  get<{ glance: GlanceData; started_at: string; version: string }>('/api/glance')

export interface Finding {
  id: number
  ts: string
  subject: string
  subject_type: string
  rule: string
  score: number
  detail?: Record<string, unknown>
  status: string
  /** The subject's current display name, resolved server-side at read time. */
  label?: string
}

export const fetchFindings = (limit = 4) =>
  get<{ findings: Finding[] }>(`/api/findings?status=open&limit=${limit}`)

export interface OpenPort {
  port: number
  service?: string
}

/**
 * scanDevice checks which conventional ports a device answers on.
 *
 * Only ever called from an explicit button press. Nothing schedules it.
 */
export async function scanDevice(id: string): Promise<{ open: OpenPort[]; checked: number }> {
  const res = await fetch(`/api/devices/${encodeURIComponent(id)}/scan`, { method: 'POST' })
  if (!res.ok) {
    throw new Error((await res.json().catch(() => ({}))).error || 'could not check')
  }
  return res.json()
}

export interface WantedSubject {
  subject: string
  subject_type: string
  label?: string
  score: number
  findings: number
}

export const fetchWanted = () => get<{ wanted: WantedSubject[] }>('/api/wanted')

export const fetchAllFindings = (limit = 200) =>
  get<{ findings: Finding[] }>(`/api/findings?status=open&limit=${limit}`)

export async function setFindingStatus(id: number, status: string): Promise<void> {
  const res = await fetch(`/api/findings/${id}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
  if (!res.ok) throw new Error('could not update')
}

// The Dispatch.

export interface PeerState {
  peer_id: string
  label?: string
  connected: boolean
  last_seen?: string
  addr?: string
  status: 'connected' | 'grey' | 'suspended'
  data_stale?: boolean
}

export interface DispatchState {
  enabled: boolean
  peer_id?: string
  listen?: string
  peers: PeerState[]
}

export interface PairingCode {
  code: string
  expires_at: string
  listen: string
}

/**
 * An error carrying the server's stable code, so the caller can say something
 * specific. A mistyped code, the wrong machine and an unreachable address are
 * three different problems with three different fixes, and "pairing failed"
 * helps with none of them.
 */
export class ApiError extends Error {
  code: string
  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

async function send<T>(path: string, method: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  raiseIfUnauthorized(res, path)
  if (!res.ok) {
    const j = await res.json().catch(() => ({}) as Record<string, string>)
    throw new ApiError(j.code ?? '', j.error ?? `request failed (${res.status})`)
  }
  return res.status === 204 ? (undefined as T) : res.json()
}

export const fetchDispatch = () => get<DispatchState>('/api/dispatch')
export const setPeering = (enabled: boolean) =>
  send<{ enabled: boolean }>('/api/dispatch/enabled', 'POST', { enabled })
export const startPairing = () => send<PairingCode>('/api/dispatch/pair', 'POST')
export const cancelPairing = () => send<void>('/api/dispatch/pair', 'DELETE')
export const joinWithCode = (addr: string, code: string, label: string) =>
  send<{ peer_id: string; label: string }>('/api/dispatch/join', 'POST', { addr, code, label })
export const setPeerTrust = (id: string, trust: 'trusted' | 'suspended') =>
  send<void>(`/api/dispatch/peers/${encodeURIComponent(id)}/trust`, 'POST', { trust })
export const unpairPeer = (id: string) =>
  send<void>(`/api/dispatch/peers/${encodeURIComponent(id)}`, 'DELETE')
/** Names a peer on this machine. Never sent anywhere; the peer is not told. */
export const renamePeer = (id: string, label: string) =>
  send<void>(`/api/dispatch/peers/${encodeURIComponent(id)}/name`, 'POST', { label })

/** A peer's destination, as served for the map. */
export interface PeerDestination {
  peer_id: string
  label?: string
  device: string
  org?: string
  country?: string
  asn?: number
  app?: string
  flows: number
  bytes: number
  lat?: number
  lon?: number
  /** Most recent hour this peer reported it. Hourly, because that is the
      resolution the peer protocol carries. */
  last_hour?: string
}

export const fetchPeerDestinations = (range: string) =>
  get<{ destinations: PeerDestination[] }>(`/api/dispatch/destinations?range=${encodeURIComponent(range)}`)

/**
 * Adapters onto the shape the map draws.
 *
 * Kept here rather than in the renderer so that map.ts knows about neither an
 * Endpoint nor a peer summary, it draws points with a key, a position and a
 * label, and everything else is somebody else's problem.
 */
export function endpointDrawable(e: Endpoint) {
  return {
    key: e.ip,
    lat: e.lat,
    lon: e.lon,
    is_internal: e.is_internal,
    conns: e.conns,
    active: e.active,
    last_flow: e.last_flow,
    title: e.org || e.rdns || e.ip,
    place: [e.city, e.country_name || e.country].filter(Boolean).join(', '),
    who: (e.processes || []).slice(0, 2).join(', '),
  }
}

export function peerDrawable(d: PeerDestination) {
  return {
    // Unique within a peer's namespace, which is where peer data lives.
    key: `${d.peer_id}|${d.org}|${d.country}|${d.app}`,
    lat: d.lat,
    lon: d.lon,
    is_internal: false,
    conns: d.flows,
    // A summary is an hour old at best, so it is never "just now". Drawn as
    // settled rather than live, which is honest: this is what a peer reported,
    // not what is happening.
    active: false,
    last_flow: 0,
    peer: true,
    title: d.org || d.country || d.device,
    place: d.country,
    who: [d.label, d.app].filter(Boolean).join(' · '),
  }
}

/**
 * Groups a peer identifier for reading: five groups of five.
 *
 * Presentation only. The API returns identifiers as stored, because a formatted
 * id is a different string and will not match anything it is compared against, 
 * which is exactly what happened when the server did this instead.
 */
export function fingerprint(id: string | undefined): string {
  if (!id || id.includes('-')) return id ?? ''
  return (id.match(/.{1,5}/g) ?? [id]).join('-')
}

/**
 * A peer's fingerprint at the length a heading can carry.
 *
 * The full form is twenty-nine characters, which is right where it is the
 * identity being checked against another screen, and wrong as a stand-in for a
 * name: it wraps to two lines and reads as though the machine were called that.
 * The first group is enough to tell two peers apart at a glance, and the full
 * value is still shown in the line below.
 */
export function shortFingerprint(id: string | undefined): string {
  const f = fingerprint(id)
  return f ? f.split('-')[0] : ''
}

export interface CaptureInterface {
  name: string
  description?: string
  addresses?: string[]
  up: boolean
  loopback: boolean
  recommended: boolean
  active: boolean
}

export interface CaptureInterfaces {
  available: boolean
  active?: string
  reason?: string
  interfaces: CaptureInterface[]
}

/** Which devices capture could run on, and which one it is on.
 *
 *  Read-only. The automatic pick is otherwise unreportable: on Windows every
 *  device is named \Device\NPF_{GUID}, so a wrong choice is indistinguishable
 *  from a quiet network until somebody reads the log. */
export const fetchCaptureInterfaces = () =>
  get<CaptureInterfaces>('/api/interfaces')

export interface Platform {
  os: string
  arch: string
  version: string
  build: string
  capture_built: boolean
  capture_published: boolean
  distributed: boolean
  data_dir: string
  db_path: string
}

/** What this binary is and where it keeps its data.
 *
 *  Read once by Help, which otherwise had per-platform instructions for five
 *  platforms and no idea which one it was being read on. Constant for the life
 *  of the process, so there is nothing to poll. */
export const fetchPlatform = () => get<Platform>('/api/platform')

/** One device belonging to a peer.
 *
 *  Deliberately not a Device: a peer sends a name and some counts, never a
 *  hardware address, a vendor, or the services a device advertises. Sharing the
 *  type would produce rows of empty columns, which reads as a lookup that failed
 *  rather than as detail that was never sent. */
export interface PeerDevice {
  peer_id: string
  label: string
  device: string
  id: string
  orgs: number
  flows: number
  bytes: number
  last_hour: number
  top_org?: string
  top_app?: string
}

export const fetchPeerDevices = (layer = 'all') =>
  get<{ devices: PeerDevice[] }>(
    `/api/dispatch/devices?range=24h&layer=${encodeURIComponent(layer)}`)
