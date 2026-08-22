import { useCallback, useMemo, useState } from 'preact/hooks'
import {
  fetchWanted, fetchAllFindings, setFindingStatus, editDevice, fmtAgo,
  TRUST_DEPUTIZED,
  type Finding, type WantedSubject,
} from './api'
import { useI18n, fill } from './i18n'
import { Freshness, usePolling } from './freshness'

/**
 * The Wanted List.
 *
 * Grouped by subject rather than listed by event, because the question is "what
 * should I look at" and the answer is a device, not a timestamp. A device with
 * three modest findings deserves attention ahead of one with a single larger
 * one, and a flat list of events buries exactly that.
 *
 * Every finding shows the sentence that justifies it. That is the whole
 * requirement from the specification, a score nobody can check is a score
 * nobody should act on, and it is why rules report facts and this file owns the
 * words.
 */

const REFRESH_MS = 20000

export function Wanted({ onSelectDevice, peered = false }: {
  onSelectDevice?: (id: string) => void
  /** Whether any machine is paired. The note is worth saying only to somebody
   *  who has peers and might reasonably expect to see their devices judged. */
  peered?: boolean
}) {
  const { t } = useI18n()
  const [subjects, setSubjects] = useState<WantedSubject[] | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [open, setOpen] = useState<string | null>(null)

  const load = useCallback(async () => {
    const [w, f] = await Promise.all([fetchWanted(), fetchAllFindings()])
    setSubjects(w.wanted)
    setFindings(f.findings)
    // **The worst subject opens itself.**
    //
    // Collapsed, this page is a list of names and a bar, it says who, and
    // nothing about why, on the one screen where why is the entire point. The
    // sentence underneath ("connected to Samsung every 10m, 71 times, at 98.8%
    // regularity") is the most useful thing the application produces, and it
    // was behind a click on a view that otherwise reads as almost empty.
    //
    // Only the first, and only when nothing is open yet: expanding everything
    // would bury the ranking, and re-expanding on every poll would fight
    // somebody who deliberately collapsed it.
    setOpen((current) => current ?? w.wanted[0]?.subject ?? null)
  }, [])

  const { updatedAt, busy, refresh } = usePolling(load, REFRESH_MS)

  // Findings indexed by subject, worst first within each.
  const bySubject = useMemo(() => {
    const m = new Map<string, Finding[]>()
    for (const f of findings) {
      const list = m.get(f.subject) ?? []
      list.push(f)
      m.set(f.subject, list)
    }
    for (const list of m.values()) {
      list.sort((a, b) => b.score - a.score || Date.parse(b.ts) - Date.parse(a.ts))
    }
    return m
  }, [findings])

  const act = async (fn: () => Promise<void>) => {
    try {
      await fn()
      await refresh()
    } catch {
      /* the status bar reports connection trouble */
    }
  }

  if (subjects === null) return <div class="chatter-loading" aria-busy="true" />

  return (
    <div class="wantedlist">
      <div class="wl-head panel">
        <div class="wl-title">
          <h2>{t.wantedList.title}</h2>
          <span>{t.wantedList.subtitle}</span>
        </div>
        <Freshness updatedAt={updatedAt} intervalMs={REFRESH_MS} busy={busy} onRefresh={refresh} />
      </div>

      {/* The other views now answer for a peer, and this one deliberately does
          not: the rules need individual connections and timings, and a peer
          sends hourly totals. Said out loud, because silence here reads as a
          peer's devices having been examined and found clean. */}
      {peered && <p class="layer-note">{t.wantedList.peerNote}</p>}

      {subjects.length === 0 ? (
        <div class="wl-clear panel">
          <b>{t.wantedList.allClear}</b>
          <span>{t.wantedList.emptySub}</span>
        </div>
      ) : (
        <div class="wl-body panel">
          {subjects.map((s) => {
            const list = bySubject.get(s.subject) ?? []
            const expanded = open === s.subject
            return (
              <section class={`wl-subject ${expanded ? 'on' : ''}`} key={s.subject}>
                <button class="wl-row" onClick={() => setOpen(expanded ? null : s.subject)}>
                  <Meter score={s.score} />
                  <span class="wl-who">{s.label || s.subject}</span>
                  <span class="wl-count">
                    {fill(t.wantedList.openFindings, { count: String(s.findings) })}
                  </span>
                </button>

                {expanded && (
                  <div class="wl-detail">
                    {list.map((f) => (
                      <article class="wl-finding" key={f.id}>
                        <p class="wl-why">{explain(t, f)}</p>
                        <div class="wl-meta">
                          <span>{t.wantedList.seen} {fmtAgo(f.ts)}</span>
                          <button class="range" onClick={() => act(() => setFindingStatus(f.id, 'cleared'))}>
                            {t.wantedList.clear}
                          </button>
                          {f.subject_type === 'device' && (
                            <button
                              class="range"
                              onClick={() => act(async () => {
                                await editDevice(f.subject, { trust: TRUST_DEPUTIZED })
                                await setFindingStatus(f.id, 'trusted')
                              })}
                            >
                              {t.wantedList.trust}
                            </button>
                          )}
                        </div>
                      </article>
                    ))}
                    {s.subject_type === 'device' && onSelectDevice && (
                      <button class="wl-open" onClick={() => onSelectDevice(s.subject)}>
                        {t.wantedList.subjectDevice} →
                      </button>
                    )}
                  </div>
                )}
              </section>
            )
          })}
        </div>
      )}
    </div>
  )
}

/**
 * explain turns a finding's facts into the sentence that justifies it.
 *
 * The rule supplied numbers; the words are here, so they can be translated. A
 * rule this does not recognise falls back to its code rather than rendering
 * nothing, a finding with no explanation is still a finding, and hiding it
 * would be worse than showing it plainly.
 */
function explain(t: any, f: Finding): string {
  const d = f.detail ?? {}
  // Port scanning has two shapes with different sentences, so the key depends
  // on the finding's own detail rather than on the rule name alone.
  let key = `e_${f.rule}`
  if (f.rule === 'port_scan') key += d.shape === 'horizontal' ? '_h' : '_v'
  // Whether a known-bad name actually resolved is the difference between
  // "reached" and "tried to reach", which is worth saying accurately.
  if (f.rule === 'threat_list') key += d.resolved ? '_r' : '_u'

  const template = t.wantedList[key]
  if (!template) return f.rule

  return fill(template, {
    org: String(d.org ?? ''),
    country: String(d.country ?? ''),
    known_orgs: String(d.known_orgs ?? ''),
    observed_days: String(d.observed_days ?? ''),
    share_pct: String(d.share_pct ?? ''),
    hits: String(d.hits ?? ''),
    regularity: String(d.regularity ?? ''),
    interval: humanInterval(Number(d.interval_secs ?? 0)),
    names: String(d.names ?? ''),
    example: String(d.example ?? ''),
    target: String(d.target ?? ''),
    ports: String(d.ports ?? ''),
    port: String(d.port ?? ''),
    hosts: String(d.hosts ?? ''),
    connected: String(d.connected ?? ''),
    protocol: String(d.protocol ?? ''),
    domain: String(d.domain ?? ''),
    connections: String(d.connections ?? ''),
    typical: String(d.typical ?? ''),
    times: String(d.times ?? ''),
  })
}

/**
 * humanInterval renders a period the way a person would say it.
 *
 * "every 300 seconds" is arithmetic; "every 5 minutes" is the same fact in a
 * form somebody can compare against what they know their devices do.
 */
function humanInterval(seconds: number): string {
  if (!seconds) return ''
  if (seconds < 90) return `${seconds}s`
  const mins = Math.round(seconds / 60)
  if (mins < 90) return `${mins}m`
  return `${Math.round(mins / 60)}h`
}

/** Meter shows a subject's combined score as a bar, not a number: the exact
 *  value is not meaningful, the comparison between rows is. */
function Meter({ score }: { score: number }) {
  const pct = Math.round(Math.min(1, Math.max(0, score)) * 100)
  return (
    <span class="wl-meter" aria-label={`${pct}`}>
      <span class="wl-meter-fill" style={{ width: `${pct}%` }} />
    </span>
  )
}
