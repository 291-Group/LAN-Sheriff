import { useEffect, useRef, useState } from 'preact/hooks'

import { useVisibleInterval } from './visibility'
import { useI18n, fill } from './i18n'

/**
 * Says how current the data on screen is, and when it will next be checked.
 *
 * A bare countdown was considered and rejected. A number ticking every second
 * draws the eye toward a clock and away from the data, and it promises a
 * precision the interval does not have, a slow request slips it. The question
 * worth answering is "can I trust what I am looking at", which is a statement
 * about the past, not the future.
 *
 * So the age of the data is the words, and the approach of the next poll is a
 * ring that fills around the refresh control: present if you look for it,
 * invisible if you do not. The control is also a button, because someone who
 * wants it now should not have to wait out the interval.
 */
export function Freshness({
  updatedAt, intervalMs, busy, onRefresh,
}: {
  /** When the data on screen was fetched. */
  updatedAt: number | null
  intervalMs: number
  busy: boolean
  onRefresh: () => void
}) {
  const { t } = useI18n()
  const [now, setNow] = useState(() => Date.now())

  // Driven by animation frames rather than a one-second interval.
  //
  // On an interval the ring was motionless for up to a second after each
  // refresh, and the CSS transition then took most of another second to catch
  // up, so the first thing it did after updating was appear stuck. Frames make
  // it start moving immediately.
  //
  // Throttled to about twelve updates a second: past that the ring is not
  // visibly smoother, and the arc only advances a fraction of a degree.
  useEffect(() => {
    let raf = 0
    let last = 0
    const tick = (t: number) => {
      if (t - last >= 80) {
        last = t
        setNow(Date.now())
      }
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [])

  const age = updatedAt === null ? 0 : Math.max(0, now - updatedAt)
  const progress = updatedAt === null ? 0 : Math.min(1, age / intervalMs)
  const remaining = Math.max(0, Math.ceil((intervalMs - age) / 1000))

  // The first load shows no busy state at all.
  //
  // On mount there is nothing on screen yet, so a spinner communicates nothing a
  // blank panel does not, and because it appears and vanishes within a few
  // hundred milliseconds, what the eye actually registers is an arc flashing on
  // and snapping back to empty. The Precinct Map showed it worst, its query
  // being the slowest. Later refreshes do show it, because then there *is*
  // content on screen and the user needs to know it is being replaced.
  const firstLoad = updatedAt === null
  const showBusy = busy && !firstLoad

  const label = updatedAt === null
    ? ''
    : age < 5000
      ? t.freshness.updatedJustNow
      : fill(t.freshness.updatedAgo, { ago: shortAge(age) })

  // Every string this label can ever show, rendered stacked in one grid cell so
  // the cell is as wide as the widest of them and the live text never resizes
  // it. Reserving a fixed width in `ch` or `em` instead would be guesswork that
  // breaks in whichever language has the longest phrase; this measures the real
  // strings in the real font.
  const widest = [
    t.freshness.updatedJustNow,
    t.freshness.refreshing,
    fill(t.freshness.updatedAgo, { ago: '88m' }),
  ]

  return (
    <span class="freshness">
      <span class="freshness-label">
        {widest.map((w, i) => (
          <span class="freshness-ghost" key={i} aria-hidden="true">{w}</span>
        ))}
        <span class="freshness-live">{showBusy ? t.freshness.refreshing : label}</span>
      </span>
      <button
        class={`freshness-btn ${showBusy ? 'busy' : ''}`}
        onClick={onRefresh}
        disabled={busy}
        title={`${t.freshness.refreshNow}, ${fill(t.freshness.nextIn, { seconds: String(remaining) })}`}
      >
        {/* While loading the arc is a short rotating segment, not a full circle.
            Drawing it full meant every page load began with a complete ring that
            snapped to empty the moment the first response arrived, which read as
            a glitch rather than as progress. */}
        <Ring progress={showBusy ? 0.22 : progress} />
        <span class="freshness-glyph" aria-hidden="true">↻</span>
      </button>
    </span>
  )
}

/** Ring draws the arc that fills as the next poll approaches. */
function Ring({ progress }: { progress: number }) {
  const r = 8
  const c = 2 * Math.PI * r
  return (
    <svg class="freshness-ring" viewBox="0 0 20 20" width="20" height="20" aria-hidden="true">
      <circle cx="10" cy="10" r={r} class="ring-track" />
      <circle
        cx="10" cy="10" r={r}
        class="ring-fill"
        stroke-dasharray={c}
        stroke-dashoffset={c * (1 - progress)}
      />
    </svg>
  )
}

/**
 * shortAge renders an age compactly: seconds, then minutes, then hours.
 *
 * Padded to two digits so that the width does not change as the count crosses
 * from 9 to 10. Combined with tabular figures this keeps every character of the
 * sentence in the same place for the whole interval.
 */
function shortAge(ms: number): string {
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${pad(s)}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${pad(m)}m`
  return `${pad(Math.floor(m / 60))}h`
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n)
}

/**
 * usePolling runs a loader on an interval and reports when it last succeeded.
 *
 * Extracted so the Roster does not have to track loading state, last-success
 * time and a manual trigger separately, and so any other view that needs a
 * freshness indicator gets the same behaviour rather than its own version.
 */
export function usePolling(load: () => Promise<void>, intervalMs: number) {
  const [updatedAt, setUpdatedAt] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const running = useRef(false)

  const run = useRef(async () => {})
  run.current = async () => {
    // A slow request must not stack up behind itself on a fast interval.
    if (running.current) return
    running.current = true
    setBusy(true)
    try {
      await load()
      setUpdatedAt(Date.now())
    } catch {
      // Leave updatedAt alone: the data on screen is still as old as it was,
      // and claiming otherwise would be a lie in the direction that matters.
    } finally {
      running.current = false
      setBusy(false)
    }
  }

  // Polling stops while the page is off screen and catches up on return, so a
  // tab left open in the background is not fetching and re-rendering into a
  // document nobody can see.
  useEffect(() => { run.current() }, [])
  useVisibleInterval(() => run.current(), intervalMs)

  return { updatedAt, busy, refresh: () => run.current() }
}
