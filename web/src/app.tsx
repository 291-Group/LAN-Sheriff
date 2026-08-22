import { useEffect, useRef, useState, useCallback, useMemo } from 'preact/hooks'
import {
  connectStream, fetchAuthStatus, fetchEgress, fetchSummary, fmtAgo, fmtBytes,
  flag, endpointLabel, logout, emptyFilter, filterIsActive, message,
  type AuthStatus, type Endpoint, type Filter, type Origin, type Summary, type StreamEvent,
  fetchDispatch, fetchPeerDestinations, endpointDrawable, peerDrawable, fingerprint,
  fetchDevices, setUnauthorizedHandler,
  type PeerState, type PeerDestination,
} from './api'
import { Watchtower } from './map'
import { Badge } from './badge'
import { Gate } from './gate'
import { Toolbar } from './toolbar'
import { SettingsPanel } from './settings'
import { Timeline } from './timeline'
import { Chatter } from './chatter'
import { Roster } from './roster'
import { Precinct } from './precinct'
import { Help } from './help'
import { LayerBar } from './layerbar'
import { Widgets } from './widgets'
import { Wanted } from './wanted'
import { Bolo } from './bolo'
import { HealthBanner } from './health'
import { Loading } from './loading'
import { Command } from './command'
import { useI18n, fill } from './i18n'
import { LanguagePicker } from './langpicker'
import { visibleInterval, pageVisible } from './visibility'

type View = 'watchtower' | 'chatter' | 'precinct' | 'roster' | 'wanted' | 'help'

/**
 * useHashView keeps the selected view in the URL.
 *
 * The hash rather than local storage, for three reasons: a refresh returns to
 * the view you were on, the browser's back button steps between views instead of
 * leaving the application, and a view is linkable. It also makes the logo's link
 * to the root mean something, it clears the hash and returns to the Watchtower.
 */
function useHashView(): [View, (v: View) => void] {
  const read = (): View => {
    const id = window.location.hash.replace(/^#/, '')
    const known = NAV.find((n) => n.id === id && n.ready)
    return known ? (id as View) : 'watchtower'
  }

  const [view, setViewState] = useState<View>(read)

  useEffect(() => {
    // Covers the back button and any hash edited by hand.
    const onHash = () => setViewState(read())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const setView = (v: View) => {
    // The default view carries no hash, so the root URL stays clean.
    const next = v === 'watchtower' ? ' ' : `#${v}`
    if (v === 'watchtower') {
      history.pushState(null, '', window.location.pathname)
      setViewState('watchtower')
    } else {
      window.location.hash = next.trim()
    }
  }

  return [view, setView]
}

const NAV: { id: View; ready: boolean; milestone?: string }[] = [
  { id: 'watchtower', ready: true },
  { id: 'chatter', ready: true },
  { id: 'precinct', ready: true },
  { id: 'roster', ready: true },
  { id: 'wanted', ready: true },
  { id: 'help', ready: true },
]

/**
 * Theme preference. This is the one thing kept in localStorage: it is a display
 * preference, not application state, and it has to be applied before the first
 * paint to avoid a flash of the wrong theme.
 */
type Theme = 'light' | 'dark'

function initialTheme(): Theme {
  const saved = localStorage.getItem('sheriff-theme')
  if (saved === 'light' || saved === 'dark') return saved
  // Light glass is the house look, so it is the default even for someone whose
  // system prefers dark. Their own toggle, once used, always wins.
  return 'light'
}

/**
 * Applies the theme to the document and remembers it.
 *
 * This deliberately writes to the DOM synchronously rather than from an effect.
 * The canvas map caches its palette by reading these CSS variables, and effects
 * run child-first: an effect here would fire *after* the map had already
 * re-read the old values, leaving the map one theme behind on every toggle.
 */
function applyTheme(theme: Theme) {
  const root = document.documentElement

  // **Transitions off for the duration of the switch.**
  //
  // A few elements carry `transition: background 0.15s` so their hover states
  // are not abrupt: the active nav item, the mode pill, the range buttons. That
  // transition cannot tell the difference between a hover and the entire
  // palette changing underneath it, so on a theme toggle those few elements
  // crossfade over 150ms while every other pixel flips at once. It reads as
  // those elements lagging behind the page, and was reported as exactly that.
  //
  // Added before the variables change and removed two frames later: one frame
  // for the new values to paint, and a second because removing it in the same
  // frame lets the transition start after all.
  root.classList.add('theme-switching')
  root.dataset.theme = theme
  requestAnimationFrame(() => {
    requestAnimationFrame(() => root.classList.remove('theme-switching'))
  })
  try {
    localStorage.setItem('sheriff-theme', theme)
  } catch {
    /* private browsing; the theme just will not persist */
  }
}

/**
 * PrivacyLine states what is actually true about this instance right now.
 *
 * "Everything stays on this machine" is the product's central claim and it is
 * false the moment peer sharing is on. Rather than soften it permanently, or
 * leave it wrong for the people who enabled peering, the line is driven by
 * what the instance is actually doing.
 *
 * Peering off (the default, and the overwhelmingly common case) keeps the
 * strong claim exactly as it was.
 */
function PrivacyLine() {
  const { t } = useI18n()
  const [peers, setPeers] = useState<number | null>(null)

  useEffect(() => {
    let cancelled = false
    // **Polled, because this can now change while the page is open.**
    //
    // This was a single read at mount, on the reasoning that peering was a
    // command-line flag and so could not change during a session. That stopped
    // being true the moment peer sharing gained a switch in Settings and a
    // pairing could complete in another tab, and the symptom was the worst
    // one available: the footer went on saying nothing was paired while a peer
    // was connected and receiving summaries. A privacy claim that is stale is
    // worse than one that is merely vague.
    //
    // Cheap enough to poll: it reads memory and one small table.
    const read = () =>
      fetch('/api/dispatch', { credentials: 'same-origin' })
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => {
          if (cancelled || !d) return
          setPeers(d.enabled ? (d.peers?.length ?? 0) : null)
        })
        .catch(() => {})
    read()
    const stop = visibleInterval(read, 5000)
    return () => { cancelled = true; stop() }
  }, [])

  // **Off looks quiet; on does not.**
  //
  // This line is the disclosure the whole peer-sharing design leans on, the
  // thing that makes sharing impossible to hide. It used to change its words
  // and nothing else: same 9.5px, same faintest grey on the page, whether it
  // said nothing leaves this machine or named the machines it goes to. A tester
  // could not find it on their own instance, which is the only test that matters
  // for a notice whose job is being noticed.
  //
  // Quiet is right when it is reassurance. It is wrong when it is a statement
  // that data is leaving.
  // The "no account, no cloud, no telemetry" half is constant and always true,
  // so it sits on its own line in the ordinary footer grey. Only the part that
  // actually changes (where this instance's observations go) takes the
  // sharing styling. Styling the constant half too made the whole block look
  // like one alarm and buried the sentence that was doing the work.
  const tail = <span class="privacy-tail">{t.app.noTelemetry}</span>

  if (peers === null) return <>{t.app.privacy} {tail}</>
  // Zero paired machines is its own sentence. "Shared only with 0 machines" is
  // both awkward and wrong: with nothing paired, nothing has been shared, and
  // the claim should say so rather than render a count of none.
  if (peers === 0) {
    return <><span class="privacy-sharing idle">{t.app.privacyPeeringNone}</span>{tail}</>
  }
  const template = peers === 1 ? t.app.privacyPeering : t.app.privacyPeeringPlural
  return (
    <>
      <span class="privacy-sharing live">{fill(template, { count: peers })}</span>
      {tail}
    </>
  )
}

/**
 * What the app knows about the session.
 *
 * # Why this is three states and not a nullable one
 *
 * It used to be `AuthStatus | null`, and null meant two unrelated things:
 * "the first check has not come back yet" and "the check failed". Both
 * rendered as an empty page, which was fine for the first because it resolves
 * within a frame or two, and unrecoverable for the second because nothing ever
 * retried it.
 *
 * That is not hypothetical. A laptop left open overnight came back to a blank
 * page that needed a manual reload: the browser had discarded the backgrounded
 * tab, silently reloaded it on wake, and the app had mounted before the local
 * service finished starting. One fetch failed, and a monitoring tool that is
 * meant to sit on a second screen for weeks had latched itself blank until
 * somebody noticed and pressed reload.
 *
 * The distinction earns its keep because the two states want opposite things:
 * `checking` wants to show nothing, and `unreachable` wants to keep trying and
 * eventually say so.
 */
type AuthState =
  | { phase: 'checking' }
  | { phase: 'unreachable'; attempts: number }
  | { phase: 'known'; status: AuthStatus }

export function App() {
  const [auth, setAuth] = useState<AuthState>({ phase: 'checking' })
  const [theme, setThemeState] = useState<Theme>(initialTheme)

  const setTheme = useCallback((t: Theme) => {
    applyTheme(t)
    setThemeState(t)
  }, [])

  // Cover the first render, and any case where the inline bootstrap did not run.
  useEffect(() => { applyTheme(theme) }, [])

  // One check at a time. Every widget polls independently, so a session that
  // ends takes several 401s in the same tick; without this they would each
  // start their own check. It also makes the handler below safe against a 401
  // on the status endpoint itself, which would otherwise recurse.
  const checking = useRef(false)

  const checkAuth = useCallback(async () => {
    if (checking.current) return
    checking.current = true
    try {
      setAuth({ phase: 'known', status: await fetchAuthStatus() })
    } catch {
      // Keep the count, so the retry below can back off rather than hammer a
      // service that is still starting.
      setAuth((prev) => ({
        phase: 'unreachable',
        attempts: prev.phase === 'unreachable' ? prev.attempts + 1 : 1,
      }))
    } finally {
      checking.current = false
    }
  }, [])

  useEffect(() => { checkAuth() }, [checkAuth])

  // Keep trying, because the usual reason for being here is a service that is
  // still coming up: a machine waking, a restart after an update, a reload that
  // won the race against the port opening. Half a second, doubling to ten, so
  // the common case heals before the reader finishes registering it and the
  // uncommon one does not turn into a reconnect storm.
  useEffect(() => {
    if (auth.phase !== 'unreachable') return
    const wait = Math.min(10000, 500 * 2 ** (auth.attempts - 1))
    const id = window.setTimeout(checkAuth, wait)
    return () => window.clearTimeout(id)
  }, [auth, checkAuth])

  // A session can end while the page is open, and every restart of the service
  // ends all of them. Re-checking turns a 401 from any poll into the sign-in
  // screen, in place of a dashboard silently frozen on the last data it held.
  useEffect(() => {
    setUnauthorizedHandler(checkAuth)
    return () => setUnauthorizedHandler(() => {})
  }, [checkAuth])

  // Coming back to the tab is the moment a stale session is most likely, and
  // the moment the reader is most likely to trust what they see.
  useEffect(() => {
    const onVisible = () => { if (pageVisible()) checkAuth() }
    document.addEventListener('visibilitychange', onVisible)
    return () => document.removeEventListener('visibilitychange', onVisible)
  }, [checkAuth])

  if (auth.phase === 'checking') return null // resolves in a frame or two
  if (auth.phase === 'unreachable') return <Unreachable attempts={auth.attempts} onRetry={checkAuth} />
  if (!auth.status.authenticated) return <Gate status={auth.status} onDone={checkAuth} />

  return <Dashboard theme={theme} setTheme={setTheme} auth={auth.status} onSignOut={checkAuth} />
}

/**
 * Shown when the dashboard cannot reach the service behind it.
 *
 * Silent for the first few attempts, on the same reasoning as `Loading`: this
 * is usually a service that is a second away from being ready, and an alarming
 * panel that appears and vanishes is worse than the brief blank it replaced.
 * It speaks up once the delay is long enough that the reader has certainly
 * noticed, and then keeps retrying behind the message, so the button is a
 * courtesy rather than the only way out.
 */
function Unreachable({ attempts, onRetry }: { attempts: number; onRetry: () => void }) {
  const { t } = useI18n()
  if (attempts < 3) return null

  return (
    <div class="gate">
      <div class="gate-card" role="alert">
        <div class="gate-head">
          <Badge />
          <h1>{t.gate.offlineTitle}</h1>
        </div>
        <p class="gate-note">{t.gate.offlineWhy}</p>
        <button type="button" class="ghost-btn" onClick={onRetry}>
          {t.gate.offlineRetry}
        </button>
      </div>
    </div>
  )
}

function Dashboard({
  theme, setTheme, auth, onSignOut,
}: {
  theme: Theme
  setTheme: (t: Theme) => void
  auth: AuthStatus
  onSignOut: () => void
}) {
  const [view, setView] = useHashView()

  // Which device the Roster should open when it is next shown.
  //
  // Set by whatever offered the device: the Wanted List, or the loudest-device
  // line in Right Now. Cleared when the reader navigates somewhere else under
  // their own steam, so that coming back to the Roster later does not reopen a
  // pane they closed twenty minutes ago.
  const [openDevice, setOpenDevice] = useState<string | undefined>(undefined)

  useEffect(() => {
    if (view !== 'roster') setOpenDevice(undefined)
  }, [view])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [endpoints, setEndpoints] = useState<Endpoint[]>([])
  // How many destinations the egress limit cut, so the panel can say so
  // instead of presenting a capped list as the whole picture.
  const [omitted, setOmitted] = useState(0)
  const [origin, setOrigin] = useState<Origin | null>(null)
  const [live, setLive] = useState(false)
  const [ticker, setTicker] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [dismissed, setDismissed] = useState(false)
  const [filter, setFilter] = useState<Filter>(emptyFilter)
  const [showSettings, setShowSettings] = useState(false)

  // **Which machines every view is showing.**
  //
  // Lifted out of the Watchtower, where it used to live along with the entire
  // notion of peer data. One control now answers for the whole dashboard, so a
  // reader cannot be looking at a peer's traffic in one view and this machine's
  // in the next without anything saying which is which.
  const [layer, setLayer] = useState('')
  const [peers, setPeers] = useState<PeerState[]>([])

  // Polled rather than read once: peering can be switched on and a machine
  // paired while this page is open, and the control has to appear when that
  // happens rather than at the next reload.
  useEffect(() => {
    let cancelled = false
    const read = () => {
      fetchDispatch()
        .then((d) => { if (!cancelled) setPeers(d.enabled ? d.peers : []) })
        .catch(() => { if (!cancelled) setPeers([]) })
    }
    read()
    const id = setInterval(read, 20_000)
    return () => { cancelled = true; clearInterval(id) }
  }, [])

  // A peer that goes away takes its layer with it. Without this the dashboard
  // would sit on the layer of a machine that is no longer paired and show an
  // empty view with no way to tell why.
  useEffect(() => {
    if (layer && layer !== 'all' && !peers.some((p) => p.peer_id === layer)) setLayer('')
  }, [peers, layer])

  const refresh = useCallback(async () => {
    try {
      const [s, e] = await Promise.all([fetchSummary(filter), fetchEgress(filter)])
      setSummary(s)
      setEndpoints(e.endpoints)
      setOmitted(e.truncated ?? 0)
      setOrigin(e.origin)
    } catch {
      /* the stream's connection state is what tells the user we are down */
    }
  }, [filter])

  useEffect(() => {
    refresh()
    // Historical windows do not move, so only poll when looking at live data.
    if (filter.from) return
    return visibleInterval(refresh, 5000)
  }, [refresh, filter.from])

  useEffect(() => {
    return connectStream(
      (ev: StreamEvent) => {
        if (ev.type === 'flow' && ev.data.phase === 'open') {
          const f = ev.data.flow
          // Loopback and LAN chatter is not news, and the browser's own
          // connection to this dashboard would otherwise dominate the feed.
          if (f.direction !== 'out') return
          setTicker(`${f.process || 'unknown app'} → ${f.dst_ip}:${f.dst_port}`)
        }
      },
      () => setLive(true),
      () => setLive(false),
    )
  }, [])

  const { t } = useI18n()
  const caps = summary?.capabilities
  const showBanner = !dismissed && (caps?.hint_code || caps?.hint)
  const navLabel = (id: View) => t.nav[id]
  const navSub = (id: View) => t.nav[`${id}Sub` as keyof typeof t.nav] as string

  return (
    <div class="shell">
      {/* A link rather than a button: it is a real navigation to the root, so
          middle-click and "open in new tab" behave the way people expect. */}
      <a class="brand panel" href="/" title={t.app.name}>
        <Badge size={26} />
        <span class="brand-name">
          {t.app.name}
          <small>{t.app.byOrg}</small>
        </span>
      </a>

      <div class="statusbar panel">
        {/* The pill is a button so a dismissed capability banner is never lost:
            clicking it brings the explanation back. */}
        <button
          class="mode-pill"
          title={t.actions.whatModeSees}
          onClick={() => { setDismissed(false); setView('help') }}
        >
          <i class={`dot ${live ? 'live' : 'down'}`} />
          {/* **Deputy Mode is not the default, it is the answer once one is
              known.** Until the first summary lands, `summary?.mode` is
              undefined and this chain fell through to Deputy: a Patrol Mode
              install announced itself as the weaker mode for as long as the
              first request took, next to three zeroes and a map saying no
              traffic had been seen. Every one of those is a specific claim, all
              four were false, and they are the first thing a reader sees on the
              machine where the request is slowest, which is a Raspberry Pi on
              first run. Saying nothing yet is the honest state, and there is a
              word for it. */}
          {!live
            ? t.status.reconnecting
            : !summary
              ? t.status.starting
              : summary.mode === 'offline'
                ? t.status.offlineMode
                : summary.mode === 'patrol'
                  ? t.status.patrolMode
                  : t.status.deputyMode}
          {caps?.hint_code && <span class="mode-more">?</span>}
        </button>
        {/* A placeholder rather than 0, for the same reason the pill no longer
            says Deputy: zero is a measurement, and there has not been one yet.
            A character rather than a blank so the bar keeps its width and the
            numbers do not shove the ticker sideways when they arrive. */}
        <span class="stat"><b>{summary ? summary.endpoints : '\u00b7'}</b><span>{t.status.destinations}</span></span>
        <span class="stat"><b>{summary ? summary.countries : '\u00b7'}</b><span>{t.status.countries}</span></span>
        {/* How much has happened, beside how much is happening. The live count
            used to be unbounded, which made it read as a running total and left
            nothing to answer that question once it was corrected to mean what
            it says. The number was already computed and sent, and displayed
            nowhere. Windowed like destinations and countries, so all three move
            together with the time selector and only "live" is fixed at two
            minutes. */}
        <span class="stat"><b>{summary ? summary.flows.toLocaleString() : '\u00b7'}</b><span>{t.status.connections}</span></span>
        <span class="stat"><b>{summary ? summary.active_flows.toLocaleString() : '\u00b7'}</b><span>{t.status.live}</span></span>

        <div class="ticker" title={t.status.latestTooltip}>
          <span class="ticker-label">{t.status.latestOut}</span>
          <span class="ticker-body">{ticker || t.status.nothingYet}</span>
        </div>

        <div class="actions">
          <button
            class="icon-btn"
            title={theme === 'dark' ? t.actions.switchToLight : t.actions.switchToDark}
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          >
            {theme === 'dark' ? '☀' : '☾'}
          </button>
          <LanguagePicker />
          <button class="icon-btn" title={t.actions.settings} onClick={() => setShowSettings(true)}>
            ⚙
          </button>
          {auth.required && (
            <button
              class="icon-btn"
              title={t.actions.signOut}
              onClick={async () => { await logout(); onSignOut() }}
            >
              ⏻
            </button>
          )}
        </div>
      </div>

      <nav class="panel">
        {NAV.map((n) => (
          <button
            key={n.id}
            class={`nav-item ${view === n.id ? 'active' : ''}`}
            disabled={!n.ready}
            onClick={() => n.ready && setView(n.id)}
            title={n.ready ? navSub(n.id) : fill(t.nav.comingIn, { milestone: n.milestone! })}
          >
            {navLabel(n.id)}
            <small>{navSub(n.id)}</small>
          </button>
        ))}
        {/* The nav's spare room, used for the questions the main views do not
            answer: what is new, what is loudest, what time is it here. */}
        <Widgets onSelectDevice={(id) => { setOpenDevice(id); setView('roster') }} />

        <div class="nav-foot">
          <PrivacyLine />
          {/* Always rendered, even before the summary has arrived. Making it
              conditional meant the element did not exist on first paint and
              appeared a moment later, shifting the whole footer, and with it
              the privacy line, which is the last thing in this pane that should
              move about while somebody is reading it. */}
          {/* Version and build together. Two builds of one version are
              otherwise indistinguishable in a bug report, and during development
              the version does not move for weeks at a time while the build does.
              The number is the commit count, so it rises on its own and nobody
              has to remember to bump it. */}
          {/* bdi for the same reason as the sign-in footer: a Latin version
              beside a number, in a sidebar that is right to left in Arabic and
              Hebrew, has its number detached and moved unless it is isolated. */}
          <span class="nav-version">
            <bdi>
              {summary?.version ?? ''}
              {summary?.build && (
                <span class="nav-build"> {fill(t.app.build, { n: summary.build })}</span>
              )}
            </bdi>
          </span>
        </div>
      </nav>

      <main>
        <HealthBanner />
        {/* The only notification channel on by default. Silent while the user
            is already looking at the findings. */}
        <Bolo onOpen={() => setView('wanted')} suppressed={view === 'wanted'} />
        {showBanner && (
          <div class="banner">
            <span>{message(t.msg, caps!.hint_code, caps!.hint)}</span>
            {caps!.enable_cmd && <Command cmd={caps!.enable_cmd} />}
            <button onClick={() => setDismissed(true)}>{t.actions.dismiss}</button>
          </div>
        )}

        {/* The Roster is not time-filtered: it shows what is on the network now.
            Leaving the range control visible would imply the list responds to it. */}
        {/* The export follows the screen. It was pinned to "egress", so the
            buttons on Radio Chatter downloaded a file of destinations while the
            reader was looking at DNS lookups: a valid CSV answering a different
            question, which is worse than an error because nothing says so until
            the file is opened. The Precinct Map is derived from destinations, so
            egress is the honest answer there. */}
        {view !== 'roster' && view !== 'help' && view !== 'wanted' && (
          <Toolbar
            filter={filter}
            onChange={setFilter}
            view={view === 'chatter' ? 'dns' : 'egress'}
            layer={layer}
          />
        )}

        {/* On every view that can answer for a layer. Help is static, and the
            Wanted List reasons only about what this machine observed, so
            neither is offered a choice it could not honour. */}
        {(view === 'watchtower' || view === 'precinct' || view === 'roster' || view === 'chatter') && (
          <LayerBar peers={peers} layer={layer} onChange={setLayer} />
        )}
        {view === 'watchtower' && <Timeline filter={filter} onChange={setFilter} />}

        {view === 'wanted' ? (
          <Wanted onSelectDevice={(id) => { setOpenDevice(id); setView('roster') }} peered={peers.length > 0} />
        ) : view === 'help' ? (
          <Help mode={summary?.mode} caps={caps} />
        ) : view === 'precinct' ? (
          <Precinct filter={filter} layer={layer} />
        ) : view === 'roster' ? (
          <Roster layer={layer} openDevice={openDevice} />
        ) : view === 'chatter' ? (
          <Chatter filter={filter} layer={layer} onFilter={(patch) => setFilter({ ...filter, ...patch })} />
        ) : view === 'watchtower' ? (
          <WatchtowerView
            layer={layer}
            origin={origin}
            endpoints={endpoints}
            omitted={omitted}
            summary={summary}
            selected={selected}
            onSelect={setSelected}
            theme={theme}
            onFilter={(patch) => setFilter({ ...filter, ...patch })}
            filtered={filterIsActive(filter)}
            onClearFilter={() => setFilter({ range: filter.range })}
          />
        ) : (
          <Stub view={view} />
        )}

        {showSettings && (
          <SettingsPanel onClose={() => setShowSettings(false)} onWiped={refresh} />
        )}
      </main>
    </div>
  )
}

function Stub({ view }: { view: View }) {
  const { t } = useI18n()
  const n = NAV.find((x) => x.id === view)!
  const label = t.nav[view]
  return (
    <div class="stub">
      <h2>{label}</h2>
      <p>{fill(t.nav.notInBuild, { name: label })}</p>
      <span class="milestone">{fill(t.nav.milestone, { milestone: n.milestone! })}</span>
    </div>
  )
}

function WatchtowerView({
  origin, endpoints, omitted, summary, selected, onSelect, theme, onFilter, filtered, onClearFilter,
  layer,
}: {
  layer: string
  origin: Origin | null
  endpoints: Endpoint[]
  omitted: number
  summary: Summary | null
  selected: string | null
  onSelect: (ip: string | null) => void
  theme: Theme
  onFilter: (patch: Partial<Filter>) => void
  filtered: boolean
  onClearFilter: () => void
}) {
  const { t } = useI18n()
  const [countries, setCountries] = useState(() => {
    try { return localStorage.getItem('sheriff-countries') === '1' } catch { return false }
  })
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const towerRef = useRef<Watchtower | null>(null)

  // Which machines the map is showing. "" means this one, which is the only
  // option unless peering is on, the control does not appear otherwise, since
  // a selector with a single choice is furniture.
  // The layer arrives from the shell now. It used to be owned here, which is
  // how peer data ended up being a Watchtower feature rather than a property of
  // the dashboard.
  const [peerDests, setPeerDests] = useState<PeerDestination[]>([])

  // **Which machine each connection belongs to.**
  //
  // Endpoints already carry the device ids that reached them; nothing rendered
  // them, so in Patrol Mode, and on the Everything layer, the list was one
  // undifferentiated pile of connections from several machines with nothing
  // saying which was which. The ids are opaque, so they are resolved to the
  // name the Roster shows.
  const [deviceNames, setDeviceNames] = useState<Record<string, string>>({})
  useEffect(() => {
    let alive = true
    fetchDevices()
      .then((d) => {
        if (!alive) return
        const m: Record<string, string> = {}
        for (const dev of d.devices ?? []) {
          m[dev.id] = dev.label || dev.name || dev.hostname || dev.ip || dev.id
        }
        setDeviceNames(m)
      })
      .catch(() => {})
    return () => { alive = false }
  }, [])
  const nameOf = (id: string) => deviceNames[id] || id

  useEffect(() => {
    if (layer === '') { setPeerDests([]); return }
    let cancelled = false
    const load = () =>
      fetchPeerDestinations('24h')
        .then((d) => { if (!cancelled) setPeerDests(d.destinations) })
        .catch(() => {})
    load()
    const stop = visibleInterval(load, 15000)
    return () => { cancelled = true; stop() }
  }, [layer])

  // What the map draws, given the chosen layer. Adapting here keeps the
  // renderer ignorant of both shapes.
  const drawn = useMemo(() => {
    const mine = endpoints.map(endpointDrawable)
    if (layer === '') return mine
    const theirs = peerDests
      .filter((d) => layer === 'all' || d.peer_id === layer)
      .map(peerDrawable)
    return layer === 'all' ? [...mine, ...theirs] : theirs
  }, [layer, endpoints, peerDests])

  // The same set the map is drawing, for the list beside it. Kept here so the
  // two cannot disagree about which machine's data is on screen.
  const shownPeers = useMemo(
    () => (layer === '' ? [] : peerDests.filter((d) => layer === 'all' || d.peer_id === layer)),
    [layer, peerDests],
  )

  useEffect(() => {
    if (!canvasRef.current || !wrapRef.current) return
    const tower = new Watchtower(canvasRef.current)
    towerRef.current = tower
    // Restore the border layer for somebody who had it on last time. Fire and
    // forget: it loads geometry, and the map is usable throughout.
    if (countries) void tower.setCountries(true)
    tower.onSelect = onSelect
    tower.onZoom = (_k, min, max) => { setZoomMin(min); setZoomMax(max) }

    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      tower.resize(width, height)
    })
    ro.observe(wrapRef.current)
    tower.start()

    return () => {
      ro.disconnect()
      tower.destroy()
      towerRef.current = null
    }
  }, [onSelect])

  useEffect(() => {
    if (origin && towerRef.current) towerRef.current.setData(origin, drawn)
  }, [origin, drawn])

  useEffect(() => { towerRef.current?.setSelected(selected) }, [selected])

  // The canvas caches its palette, so it has to be told when the theme changes.
  useEffect(() => { towerRef.current?.refreshTheme() }, [theme])

  const located = endpoints.filter((e) => e.lat || e.lon)
  // A stored record is not a slow live one. Every "yet" and "still" on this
  // screen promised a change that will never come, while the banner directly
  // above it said nothing is being captured. The screen contradicted itself.
  const record = summary?.mode === 'offline'
  // Said once, where the coarseness is visible, rather than left for somebody
  // to notice that every US arc lands on the same point.
  const layerNote = layer !== '' ? (
    <p class="layer-note">{t.watchtower.layerCountryOnly}</p>
  ) : null

  // The map has to start the arcs somewhere, and when this network's own
  // position is not known it uses a neutral point, which lands in North Africa
  // and looks exactly like a real origin. Without this note a user reasonably
  // concludes their traffic is routed through the Sahara, or that the map is
  // broken. True on every fresh install for the first few seconds, and
  // permanently for anyone offline.
  const originNote = origin && !origin.known ? (
    <p class="layer-note">
      {record ? t.watchtower.originUnknownRecord : t.watchtower.originUnknown}
    </p>
  ) : null

  const sel = endpoints.find((e) => e.ip === selected) || null

  // **Peer rows are selectable too.**
  //
  // They were not, and the reason recorded was that a peer sends no address so
  // there is nothing to select. True about the address, wrong about the row: a
  // reader who clicks one of this machine's destinations and gets a panel, then
  // clicks a peer's and gets nothing, learns that the feature is broken rather
  // than that peer data is thinner than their own.
  //
  // Kept local rather than lifted alongside `selected`: that one drives the map,
  // which keys arcs by address, and a peer has none to key on.
  // Mirrors the map's own limits so the controls can dim. Reported by the map
  // rather than recomputed here: it owns the clamp, and a second copy of that
  // arithmetic is a second thing to get wrong.
  const [zoomMin, setZoomMin] = useState(true)
  const [zoomMax, setZoomMax] = useState(false)

  // **How many of a peer's destinations to show before folding the rest away.**
  //
  // On the Everything layer these sit above this machine's own list, so with
  // three peers reporting nine destinations between them your own network was
  // below the fold and you had to scroll past somebody else's television to
  // reach it. With ten peers it would be off the screen entirely.
  //
  // Not applied when a single peer is selected: that layer is a request to see
  // that machine, and holding its rows back would be answering a different
  // question.
  const PEER_ROWS = 6
  const [showAllPeers, setShowAllPeers] = useState(false)

  const [peerKey, setPeerKey] = useState<string | null>(null)
  const selPeer = peerKey ? shownPeers.find((d) => peerRowKey(d) === peerKey) ?? null : null

  // One panel, so one selection. Choosing either clears the other rather than
  // leaving two rows lit with one panel between them.
  const selectPeer = (k: string | null) => { setPeerKey(k); if (k) onSelect(null) }
  const selectEndpoint = (ip: string | null) => { setPeerKey(null); onSelect(ip) }

  return (
    <div class="watchtower">
      {/* **Above the map, not on it.**

          These were absolutely positioned over the top-left of the canvas,
          which put an explanation on top of the very thing it explains: arcs
          and coastlines ran underneath the words, and the note covered the part
          of the map somebody was most likely to be looking at. Giving them a
          plate made them readable and did not make them any less in the way.

          In the flow above the panel they cover nothing, need no plate, and sit
          next to the layer control that caused them. */}
      {(layerNote || originNote) && (
        <div class="map-notes">
          {layerNote}
          {originNote}
        </div>
      )}

      <div class="map-wrap panel" ref={wrapRef}>
        <canvas ref={canvasRef} />
        {/* The wheel already zooms, but nothing on screen said so, and a wheel
            is not available to everybody. These are the discoverable half.
            Disabled at the limits rather than silently doing nothing, because
            a button that never responds reads as broken. */}
        <div class="map-zoom">
          {/* Borders and country names, remembered between visits. The geometry
              is fetched on first use, so the first press can take a moment on a
              slow connection and the map simply stays as it was until it
              arrives. */}
          <button
            class={`map-zoom-btn map-countries ${countries ? 'on' : ''}`}
            onClick={() => {
              const next = !countries
              setCountries(next)
              try { localStorage.setItem('sheriff-countries', next ? '1' : '0') } catch { /* private browsing */ }
              towerRef.current?.setCountries(next)
            }}
            title={t.watchtower.countries}
            aria-label={t.watchtower.countries}
            aria-pressed={countries}
          >◍</button>
          <button
            class="map-zoom-btn"
            onClick={() => towerRef.current?.zoomBy(1.6)}
            disabled={zoomMax}
            title={t.watchtower.zoomIn}
            aria-label={t.watchtower.zoomIn}
          >+</button>
          <button
            class="map-zoom-btn"
            onClick={() => towerRef.current?.zoomBy(1 / 1.6)}
            disabled={zoomMin}
            title={t.watchtower.zoomOut}
            aria-label={t.watchtower.zoomOut}
          >−</button>
        </div>
        {/* Gated on the summary having arrived. "No outbound traffic observed
            yet" is a finding, and before the first response there has been no
            looking: on a cold start this told the reader the network was silent
            while the request that would have contradicted it was still in
            flight. Loading waits 180ms before it draws anything, so a fast
            answer still shows no spinner at all. */}
        {!summary && <Loading />}
        {summary && located.length === 0 && (
          <div class="map-empty">
            <h2>
              {filtered
                ? t.watchtower.noMatchTitle
                : record
                  ? t.status.offlineMode
                  : t.watchtower.watchingTitle}
            </h2>
            <p>
              {filtered
                ? t.watchtower.noMatch
                : endpoints.length > 0
                  ? (record ? t.watchtower.recordNotLocated : t.watchtower.watchingNotLocated)
                  : (record ? t.watchtower.recordEmpty : t.watchtower.watchingNoTraffic)}
            </p>
            {filtered && (
              <button class="ghost-btn map-empty-action" onClick={onClearFilter}>
                {t.toolbar.clearAll}
              </button>
            )}
          </div>
        )}
        {/* The map has to start the arcs somewhere, and when this network's own
            position is not known it uses a neutral point, which lands in North
            Africa and looks exactly like a real origin. Without this note a user
            reasonably concludes their traffic is routed through the Sahara, or
            that the map is broken. True on every fresh install for the first few
            seconds, and permanently for anyone offline. */}
        {/* The legend describes what is on screen, so it changes with the layer.
            A peer's arcs are hourly summaries (not live, not closed) and
            labelling them "closed" would be a plain misstatement. */}
        <div class="legend">
          <span><i style="background:var(--star)" />{t.watchtower.legendYou}</span>
          {layer === '' ? (<>
            <span><i style="background:var(--warm)" />{t.watchtower.legendJustNow}</span>
            <span><i style="background:var(--calm)" />{t.watchtower.legendActive}</span>
            <span><i style="background:var(--arc-idle)" />{t.watchtower.legendClosed}</span>
          </>) : layer === 'all' ? (<>
            <span><i style="background:var(--warm)" />{t.watchtower.legendJustNow}</span>
            <span><i style="background:var(--calm)" />{t.watchtower.legendActive}</span>
            {/* Everything draws this machine's destinations and a peer's at
                once, so both need a key. Grey was labelled "reported by a peer"
                while your own closed connections were drawn in that same grey,
                so the legend stated something untrue. */}
            <span><i style="background:var(--arc-idle)" />{t.watchtower.legendClosed}</span>
            <span><i style="background:var(--arc-peer)" />{t.watchtower.legendReported}</span>
          </>) : (
            <span><i style="background:var(--arc-peer)" />{t.watchtower.legendReported}</span>
          )}
        </div>
        <div class="attrib">
          {t.watchtower.attribution} <a href="https://db-ip.com" target="_blank" rel="noreferrer">DB-IP</a> (CC BY 4.0)
        </div>
      </div>

      <div class="side panel">
        <div class="side-head">
          <h2>{t.watchtower.destinations}</h2>
          <p>
            {/* **Counts what this list is showing, not what this machine saw.**
                It was always endpoints.length, so selecting a peer left the
                heading reading "600 seen in this period, 396 quieter
                destinations not shown" directly above a list containing none of
                them: every row below belonged to the peer, and both numbers
                described this machine. The omitted note goes with it, because a
                peer list is not capped the same way. */}
            {fill(t.watchtower.seenIn, {
              count: layer === ''
                ? endpoints.length
                : layer === 'all'
                  ? endpoints.length + shownPeers.length
                  : shownPeers.length,
            })}
            {/* Same sentence the Precinct Map uses for the same idea. A capped
                list presented as the whole picture is a lie told most
                confidently to whoever has the most to look at. */}
            {omitted > 0 && (layer === '' || layer === 'all') &&
              ` · ${fill(t.precinct.truncated, { count: String(omitted) })}`}
            {summary && !summary.capabilities.byte_counts && ` · ${t.watchtower.volumesNeedPatrol}`}
          </p>
        </div>

        {/* No empty state here on purpose. An empty list means no endpoints,
            which means none are located either, so the stub over the map is
            always showing this exact sentence already, with a heading and a
            way to clear the filter. Printing it twice was worst on a narrow
            screen, where the map stacks above this panel and the two identical
            paragraphs ended up adjacent. The heading above already reads
            "Seen in 0". */}
        <div class="ep-list">
          {/* **Peer destinations, named by the machine that reported them.**

              The map drew a peer's destinations while this list showed only
              this machine's, whatever layer was chosen. So on Everything there
              were arcs on screen belonging to another machine and nothing
              anywhere saying which machine, or even that a list of them
              existed. With more than one peer they were indistinguishable from
              each other as well.

              A peer reports a country and an organization, never an address,
              so these carry no IP, cannot be selected, and cannot be filtered
              on. They are hourly summaries and are shown as such. */}
          {layer !== '' && shownPeers.length > 0 && (
            <>
              <div class="ep-peer-head">{t.watchtower.legendReported}</div>
              {(layer === 'all' && !showAllPeers
                ? shownPeers.slice(0, PEER_ROWS)
                : shownPeers).map((d) => (
                <button
                  class={`ep ep-peer ${peerRowKey(d) === peerKey ? 'sel' : ''}`}
                  key={peerRowKey(d)}
                  onClick={() => selectPeer(peerRowKey(d) === peerKey ? null : peerRowKey(d))}
                >
                  <div class="ep-top">
                    <span class="ep-org">{d.org || d.country || d.device}</span>
                    <span class="ep-flag">{flag(d.country)} {d.country || '??'}</span>
                  </div>
                  <div class="ep-sub">
                    {d.label || fingerprint(d.peer_id)}
                    {d.device ? ` \u00b7 ${d.device}` : ''}
                    {' \u00b7 '}
                    {fill(d.flows === 1 ? t.watchtower.connections : t.watchtower.connectionsPlural,
                          { count: d.flows })}
                    {/* When the peer last reported it. Every local row on this
                        page carries a time and these did not, so a destination
                        from another machine gave no way to tell whether it
                        happened minutes ago or was the last thing that peer
                        sent before it went offline. Hourly, because that is the
                        resolution the peer protocol carries; saying more would
                        be inventing precision. */}
                    {d.last_hour && (
                      <>
                        {' \u00b7 '}
                        {fmtAgo(d.last_hour)}
                      </>
                    )}
                  </div>
                  {d.app && <div class="ep-procs"><span class="chip">{d.app}</span></div>}
                </button>
              ))}
              {layer === 'all' && !showAllPeers && shownPeers.length > PEER_ROWS && (
                <button class="ep-more" onClick={() => setShowAllPeers(true)}>
                  {fill(t.watchtower.peerMore, { n: shownPeers.length - PEER_ROWS })}
                </button>
              )}
            </>
          )}
          {/* Hidden when a single peer's layer is chosen: the map is showing
              only that peer's destinations, and listing this machine's
              underneath would not match what is drawn. */}
          {(layer === '' || layer === 'all') && endpoints.map((e) => (
            <button
              key={e.ip}
              class={`ep ${e.ip === selected ? 'sel' : ''}`}
              onClick={() => selectEndpoint(e.ip === selected ? null : e.ip)}
            >
              <div class="ep-top">
                {/* bdi around anything the network named rather than we did.
                    "Amazon.com, Inc." is Latin with a trailing full stop, and in
                    an Arabic page the bidi algorithm moves that stop to the far
                    end: the list read ".Amazon.com, Inc". The address below has
                    the same problem, with its digits detached instead. */}
                <span class="ep-org"><bdi>{endpointLabel(e)}</bdi></span>
                <span
                  class="ep-flag clickable"
                  title={e.country ? fill(t.toolbar.showOnly, { value: e.country_name || e.country }) : undefined}
                  onClick={(ev) => { if (e.country) { ev.stopPropagation(); onFilter({ country: e.country }) } }}
                >
                  {flag(e.country)} {e.country || '??'}
                </span>
              </div>
              <div class="ep-sub">
                <bdi>{e.ip}</bdi> ·{' '}
                {fill(e.conns === 1 ? t.watchtower.connections : t.watchtower.connectionsPlural,
                      { count: e.conns })} · {fmtAgo(e.last_flow)}
              </div>
              {/* Which machine reached it. In Patrol Mode this list holds
                  connections from every device on the network at once, and
                  without this there was nothing saying which row belonged to
                  which machine. */}
              {e.devices && e.devices.length > 0 && (
                <div class="ep-devices">
                  {e.devices.slice(0, 3).map((d) => (
                    <span class="chip device" key={d}>{nameOf(d)}</span>
                  ))}
                  {e.devices.length > 3 && (
                    <span class="chip device more">+{e.devices.length - 3}</span>
                  )}
                </div>
              )}
              {e.processes && e.processes.length > 0 && (
                <div class="ep-procs">
                  {e.processes.slice(0, 3).map((p) => (
                    <span
                      class="chip clickable"
                      key={p}
                      title={fill(t.toolbar.showOnly, { value: p })}
                      onClick={(ev) => { ev.stopPropagation(); onFilter({ process: p }) }}
                    >
                      {p}
                    </span>
                  ))}
                </div>
              )}
            </button>
          ))}

        </div>

        {sel && <RapSheet e={sel} nameOf={nameOf} onClose={() => onSelect(null)} />}
        {selPeer && <PeerSheet d={selPeer} onClose={() => setPeerKey(null)} />}
      </div>
    </div>
  )
}

/** Identifies one peer row.
 *
 *  A peer destination has no address, so there is no natural identity: the
 *  reporting peer, the organization, the country and the application together
 *  are what the row is. Built here rather than inline so the key that renders a
 *  row and the key that selects it cannot drift apart. */
function peerRowKey(d: PeerDestination): string {
  return `${d.peer_id}|${d.org}|${d.country}|${d.app}`
}

/**
 * The Rap Sheet's counterpart for something a peer reported.
 *
 * A separate component rather than a mode of RapSheet, for the same reason
 * store.PeerDestination is not a types.Endpoint: nearly every field the Rap
 * Sheet shows is one a peer never sends. Sharing the component would mean a
 * panel of blanks and a steady pull towards filling them in with something.
 *
 * So it shows what a peer does send, and then says plainly why there is no more
 * to show. That sentence is doing real work: this panel is thinner than the one
 * next to it, and without a reason the difference reads as data that failed to
 * load rather than as the privacy guarantee the whole feature rests on.
 */
function PeerSheet({ d, onClose }: { d: PeerDestination; onClose: () => void }) {
  const { t } = useI18n()
  return (
    <div class="rapsheet">
      <button class="close" onClick={onClose} title={t.actions.close}>×</button>
      <h3>{d.org || d.country || d.device}</h3>
      <dl>
        <dt>{t.rapsheet.reportedBy}</dt>
        <dd>{d.label || fingerprint(d.peer_id)}</dd>
        {d.device && (<><dt>{t.rapsheet.devices}</dt><dd>{d.device}</dd></>)}
        {d.org && (
          <><dt>{t.rapsheet.organization}</dt><dd>{d.org}{d.asn ? ` (AS${d.asn})` : ''}</dd></>
        )}
        <dt>{t.rapsheet.location}</dt>
        <dd>{d.country ? `${flag(d.country)} ${d.country}` : t.rapsheet.unknown}</dd>
        <dt>{t.rapsheet.connections}</dt><dd>{d.flows}</dd>
        {/* Bytes only when there are some. A peer in Deputy Mode measures no
            volumes, so a flat zero here would read as "nothing was carried"
            rather than "nobody counted". */}
        {d.bytes > 0 && (<><dt>{t.rapsheet.traffic}</dt><dd>{fmtBytes(d.bytes)}</dd></>)}
        {d.app && (<><dt>{t.rapsheet.apps}</dt><dd>{d.app}</dd></>)}
      </dl>
      <p class="rapsheet-note">{t.rapsheet.peerNote}</p>
    </div>
  )
}

function RapSheet(
  { e, nameOf, onClose }:
  { e: Endpoint; nameOf: (id: string) => string; onClose: () => void },
) {
  const { t } = useI18n()
  const location = [e.city, e.country_name || e.country].filter(Boolean).join(', ')
  const measured = e.bytes_out || e.bytes_in

  return (
    <div class="rapsheet">
      <button class="close" onClick={onClose} title={t.actions.close}>×</button>
      <h3><bdi>{endpointLabel(e)}</bdi></h3>
      <dl>
        <dt>{t.rapsheet.address}</dt><dd>{e.ip}</dd>
        {e.rdns && <><dt>{t.rapsheet.reverseDns}</dt><dd>{e.rdns}</dd></>}
        {e.org && (
          <><dt>{t.rapsheet.organization}</dt><dd>{e.org}{e.asn ? ` (AS${e.asn})` : ''}</dd></>
        )}
        <dt>{t.rapsheet.location}</dt><dd>{location || t.rapsheet.unknown}</dd>
        {e.ports && e.ports.length > 0 && (
          <><dt>{t.rapsheet.ports}</dt><dd>{e.ports.slice(0, 8).join(', ')}</dd></>
        )}
        {/* Which machine reached it. Patrol Mode fills this list with every
            device on the network, and this panel described the destination in
            ten ways without once saying who had contacted it. */}
        {e.devices && e.devices.length > 0 && (
          <><dt>{t.rapsheet.devices}</dt>
            <dd>{e.devices.map(nameOf).join(', ')}</dd></>
        )}
        <dt>{t.rapsheet.connections}</dt><dd>{e.conns}</dd>
        <dt>{t.rapsheet.traffic}</dt>
        <dd>
          {measured
            ? fill(t.rapsheet.outIn, { out: fmtBytes(e.bytes_out), in: fmtBytes(e.bytes_in) })
            : t.rapsheet.notMeasured}
        </dd>
        {e.processes && e.processes.length > 0 && (
          <><dt>{t.rapsheet.apps}</dt><dd>{e.processes.join(', ')}</dd></>
        )}
        <dt>{t.rapsheet.firstSeen}</dt><dd>{fmtAgo(e.first_seen)}</dd>
        <dt>{t.rapsheet.lastSeen}</dt><dd>{fmtAgo(e.last_flow)}</dd>
      </dl>
    </div>
  )
}
