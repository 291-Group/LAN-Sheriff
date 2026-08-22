import { useEffect, useState } from 'preact/hooks'
import { fetchGlance, fetchFindings, type Finding, type GlanceData } from './api'
import { useI18n, fill } from './i18n'
import { visibleInterval } from './visibility'

/**
 * The sidebar widgets.
 *
 * They answer one question the main views do not: has anything changed since I
 * last looked? That is the question that makes somebody open a network monitor,
 * and every figure here is comparative or superlative for that reason, what is
 * new, what is loudest, when this network is normally quiet. A running total of
 * connections would be a number nobody can act on.
 *
 * Collapsed state is remembered, because a panel that reopens itself on every
 * visit is a panel the user has to close forever.
 */

const REFRESH_MS = 60000

export function Widgets({ onSelectDevice }: { onSelectDevice?: (id: string) => void }) {
  const { t } = useI18n()
  const [data, setData] = useState<{ glance: GlanceData; started_at: string } | null>(null)
  const [wanted, setWanted] = useState<Finding[] | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [res, w] = await Promise.all([fetchGlance(), fetchFindings(4)])
        if (!cancelled) { setData(res); setWanted(w.findings) }
      } catch {
        // The status bar already reports an unreachable server.
      }
    }
    load()
    const stop = visibleInterval(load, REFRESH_MS)
    return () => { cancelled = true; stop() }
  }, [])

  const g = data?.glance

  return (
    <div class="widgets">
      <Widget id="now" title={t.widgets.nowTitle} defaultOpen>
        <Clock />
        {data && <div class="w-sub">{fill(t.widgets.upFor, { time: uptime(data.started_at) })}</div>}
        {g && (
          <div class="w-sub">
            {fill(t.widgets.devicesOnline, {
              online: String(g.devices_online),
              known: String(g.devices_known),
            })}
          </div>
        )}
      </Widget>

      <Widget id="tally" title={t.widgets.tallyTitle} defaultOpen>
        {g && (g.new_orgs > 0 || g.new_devices > 0) ? (
          <>
            {g.new_orgs > 0 && (
              <div class="w-line">
                <b>{g.new_orgs}</b>
                <span>{fill(t.widgets.newOrgs, { count: '' }).trim()}</span>
              </div>
            )}
            {g.new_devices > 0 && (
              <div class="w-line">
                <b>{g.new_devices}</b>
                <span>{fill(t.widgets.newDevices, { count: '' }).trim()}</span>
              </div>
            )}
          </>
        ) : (
          <div class="w-sub">{g ? t.widgets.nothingNew : ''}</div>
        )}
      </Widget>

      {/* Open by default like the other two. It was the only one that started
          collapsed, so the sidebar came up with one section shut for no reason
          a reader could see. */}
      <Widget id="habits" title={t.widgets.loudest} defaultOpen>
        {g?.loudest_device ? (
          <button
            class="w-link"
            onClick={() => g.loudest_id && onSelectDevice?.(g.loudest_id)}
            title={fill(t.widgets.connections, { count: (g.loudest_conns ?? 0).toLocaleString() })}
          >
            {g.loudest_device}
          </button>
        ) : (
          <div class="w-sub">, </div>
        )}
        <div class="w-sub">
          {g && g.quietest_hour >= 0
            ? fill(t.widgets.quietest, { hour: formatHour(g.quietest_hour) })
            : t.widgets.needHistory}
        </div>
      </Widget>

      {/* Last, and its own card rather than another collapsible row: it is the
          one thing here that may need acting on, and it should read as a notice
          board pinned below the readouts rather than as one more statistic. */}
      <MostWanted findings={wanted} onSelect={onSelectDevice} />
    </div>
  )
}

/**
 * Clock shows the local time, which is the reference point for everything else
 * on screen, "quietest around 18:00" means nothing without knowing it is 15:40.
 *
 * Ticks on a one-second interval aligned to the second boundary, so the display
 * changes when the clock does rather than up to a second late.
 */
function Clock() {
  const { lang } = useI18n()
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    let timer: number
    const schedule = () => {
      // Aligned to the next whole second rather than a fixed interval, which
      // would drift and make the display lag the actual time.
      timer = window.setTimeout(() => {
        setNow(new Date())
        schedule()
      }, 1000 - (Date.now() % 1000))
    }
    schedule()
    return () => clearTimeout(timer)
  }, [])

  return (
    <time class="w-clock" dateTime={now.toISOString()}>
      {now.toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
    </time>
  )
}

function Widget({
  id, title, defaultOpen = false, children,
}: {
  id: string
  title: string
  defaultOpen?: boolean
  children: preact.ComponentChildren
}) {
  const key = `lan-sheriff.widget.${id}`
  const [open, setOpen] = useState(() => {
    const saved = localStorage.getItem(key)
    return saved === null ? defaultOpen : saved === '1'
  })

  const toggle = () => {
    setOpen((v) => {
      localStorage.setItem(key, v ? '0' : '1')
      return !v
    })
  }

  return (
    <section class={`widget ${open ? 'open' : ''}`}>
      <button class="w-head" onClick={toggle} aria-expanded={open}>
        <span class="w-caret" aria-hidden="true">›</span>
        {title}
      </button>
      {open && <div class="w-body">{children}</div>}
    </section>
  )
}

/** formatHour renders an hour of the day in the viewer's own convention. */
function formatHour(hour: number): string {
  const d = new Date()
  d.setHours(hour, 0, 0, 0)
  return d.toLocaleTimeString(undefined, { hour: 'numeric' })
}

/** uptime renders how long the process has been running, coarsely. */
function uptime(startedAt: string): string {
  const ms = Date.now() - new Date(startedAt).getTime()
  const mins = Math.floor(ms / 60000)
  if (mins < 60) return `${Math.max(0, mins)}m`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ${mins % 60}m`
  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}

/**
 * The Most Wanted card.
 *
 * Deliberately not a single "wanted level" for the network. One aggregate number
 * cannot be explained, cannot be acted on, and would swing alarmingly as counts
 * move, which is exactly the black-box scoring the specification rules out. A
 * count is a fact; a level is a verdict nobody can check.
 *
 * So it lists actual subjects, each with the reason it was raised and a severity
 * you can click through to. Stars because the badge is already a five-point
 * star, so the vocabulary exists.
 *
 * The empty state is the common one, a healthy network has nothing wanted most
 * of the time, so it has to read as a clean bill of health rather than as a
 * view that failed to load.
 */
function MostWanted({
  findings, onSelect,
}: {
  findings: Finding[] | null
  onSelect?: (id: string) => void
}) {
  const { t } = useI18n()

  if (findings === null) return null

  // Ordered by severity, not by time.
  //
  // The endpoint returns newest first, which is right for the full Wanted List, 
  // that view is a log. A card called "most wanted" that puts a one-star arrival
  // above a three-star one is simply mislabelled. Ties break on recency.
  const ranked = [...findings].sort((a, b) =>
    b.score - a.score || Date.parse(b.ts) - Date.parse(a.ts))

  const shown = ranked.slice(0, 3)
  const extra = ranked.length - shown.length
  const quiet = findings.length === 0

  return (
    <section class={`wanted-card ${quiet ? 'quiet' : ''}`}>
      <header class="wanted-head">
        <span class="wanted-title">{t.wanted.wantedTitle}</span>
        {!quiet && (
          <span class="wanted-count">
            {fill(t.wanted.wantedCount, { count: String(findings.length) })}
          </span>
        )}
      </header>

      {quiet ? (
        <div class="wanted-quiet">
          <b>{t.wanted.allQuiet}</b>
          <span>{t.wanted.allQuietSub}</span>
        </div>
      ) : (
        <div class="wanted-list">
          {shown.map((f) => (
            <button
              key={f.id}
              class="wanted-row"
              onClick={() => f.subject_type === 'device' && onSelect?.(f.subject)}
            >
              <span class="wanted-who">{f.label || String(f.detail?.ip ?? f.subject)}</span>
              <Stars n={starsFor(f.score)} />
              <span class="wanted-why">{(t.rule as any)[f.rule] ?? f.rule}</span>
            </button>
          ))}
          {extra > 0 && (
            <div class="wanted-more">{fill(t.wanted.andMore, { count: String(extra) })}</div>
          )}
        </div>
      )}
    </section>
  )
}

/**
 * starsFor maps a finding's score to one, two or three stars.
 *
 * Three bands rather than five: the scoring is rule-based and honest about being
 * coarse, and five levels would imply a precision the engine does not have.
 */
function starsFor(score: number): number {
  if (score >= 0.9) return 3
  if (score >= 0.7) return 2
  return 1
}

function Stars({ n }: { n: number }) {
  return (
    <span class={`wanted-stars ${n >= 3 ? 'max' : ''}`} aria-label={`${n}`}>
      {[1, 2, 3].map((i) => (
        <span key={i} class={i <= n ? 'on' : ''} aria-hidden="true">★</span>
      ))}
    </span>
  )
}
