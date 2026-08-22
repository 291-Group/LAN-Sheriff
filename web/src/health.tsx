import { useEffect, useState } from 'preact/hooks'
import { fetchHealth, type IngestHealth } from './api'
import { useI18n, fill } from './i18n'
import { visibleInterval } from './visibility'

/**
 * Says out loud when observations are not reaching storage.
 *
 * The failure it exists for: a schema mismatch makes every flow write fail
 * while the dashboard carries on serving normally. The map draws, the endpoint
 * list grows, and the timeline simply stops filling, which reads as a quiet
 * network rather than a broken one.
 *
 * Deliberately not dismissible. The other banner describes a capability the user
 * may reasonably not want; this one means data is being lost right now, and
 * hiding it would return to exactly the state that caused the problem.
 */
export function HealthBanner() {
  const { t } = useI18n()
  const [health, setHealth] = useState<IngestHealth | null>(null)

  useEffect(() => {
    let cancelled = false
    const check = async () => {
      try {
        const res = await fetchHealth()
        if (!cancelled) setHealth(res.ingest ?? null)
      } catch {
        // A failed health check is not itself evidence of a problem: the status
        // bar already reports when the server is unreachable.
      }
    }
    check()
    const stop = visibleInterval(check, 15000)
    return () => { cancelled = true; stop() }
  }, [])

  if (!health || health.consecutive_failures === 0) return null

  return (
    <div class="banner error" role="alert">
      <span>
        <b>{t.health.title}</b>
        <br />
        {fill(t.health.body, { error: health.last_error ?? '' })}
      </span>
      <span class="milestone">
        {fill(t.health.failures, { count: String(health.consecutive_failures) })}
      </span>
    </div>
  )
}
