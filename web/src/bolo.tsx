import { useCallback, useEffect, useRef, useState } from 'preact/hooks'
import { fetchAllFindings, type Finding } from './api'
import { useI18n, fill } from './i18n'
import { visibleInterval } from './visibility'

/**
 * The in-app alert for a new finding.
 *
 * The only notification channel on by default, per the specification, and the
 * design follows from one observation: an alert that interrupts you about
 * something you already knew is worse than no alert at all, because it teaches
 * you to close the next one without reading it.
 *
 * So three rules:
 *
 *   - **Nothing is announced twice.** Findings already shown are remembered
 *     across reloads, not just for the session.
 *   - **Nothing is announced on first run.** Everything is new to somebody who
 *     has just installed the application, and a wall of alerts on first launch
 *     is the fastest way to make them all worthless. The existing set is marked
 *     seen silently.
 *   - **It waits its turn.** A finding raised while the user is looking at the
 *     Wanted List does not need a banner about the Wanted List.
 */

const POLL_MS = 30000
const SEEN_KEY = 'lan-sheriff.findings.seen'

export function Bolo({
  onOpen, suppressed,
}: {
  onOpen: () => void
  /** True when the user is already looking at the findings. */
  suppressed?: boolean
}) {
  const { t } = useI18n()
  const [queue, setQueue] = useState<Finding[]>([])
  const seen = useRef<Set<number>>(loadSeen())
  const primed = useRef(false)

  const markSeen = useCallback((ids: number[]) => {
    for (const id of ids) seen.current.add(id)
    saveSeen(seen.current)
  }, [])

  useEffect(() => {
    let cancelled = false

    const check = async () => {
      let findings: Finding[]
      try {
        findings = (await fetchAllFindings(50)).findings
      } catch {
        return // the status bar reports an unreachable server
      }
      if (cancelled) return

      const fresh = findings.filter((f) => !seen.current.has(f.id))

      // The first pass establishes what already existed. Announcing all of it
      // would greet a new user with a wall of alerts about their own household.
      if (!primed.current) {
        primed.current = true
        markSeen(findings.map((f) => f.id))
        return
      }
      if (fresh.length === 0) return

      markSeen(fresh.map((f) => f.id))
      setQueue((q) => [...fresh.sort((a, b) => b.score - a.score), ...q].slice(0, 5))
    }

    check()
    const stop = visibleInterval(check, POLL_MS)
    return () => { cancelled = true; stop() }
  }, [markSeen])

  if (suppressed || queue.length === 0) return null

  const top = queue[0]
  const extra = queue.length - 1

  return (
    <div class="bolo panel" role="status">
      <div class="bolo-text">
        <b>{t.bolo.title}</b>
        <span>{(t.ruleName as any)[top.rule] ?? top.rule}, {top.label || top.subject}</span>
        {extra > 0 && (
          <span class="bolo-more">{fill(t.bolo.more, { count: String(extra) })}</span>
        )}
      </div>
      <button class="range on" onClick={() => { setQueue([]); onOpen() }}>{t.bolo.view}</button>
      <button class="range" onClick={() => setQueue([])}>{t.bolo.dismiss}</button>
    </div>
  )
}

/**
 * The set of findings already announced, remembered across reloads.
 *
 * Bounded: a finding id is an integer and the list would otherwise grow without
 * limit over the life of an install. The newest few hundred is more than enough,
 * since older findings expire anyway.
 */
function loadSeen(): Set<number> {
  try {
    const raw = localStorage.getItem(SEEN_KEY)
    if (!raw) return new Set()
    return new Set(JSON.parse(raw) as number[])
  } catch {
    return new Set()
  }
}

function saveSeen(seen: Set<number>) {
  try {
    const ids = [...seen].sort((a, b) => b - a).slice(0, 500)
    localStorage.setItem(SEEN_KEY, JSON.stringify(ids))
  } catch {
    /* private browsing; alerts will simply repeat after a reload */
  }
}
