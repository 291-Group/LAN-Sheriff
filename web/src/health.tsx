import { useEffect, useState } from 'preact/hooks'
import { fetchHealth, type IngestHealth, type StorageHealth } from './api'
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
 * It also says when the database itself is damaged, which is a different
 * failure: writes can keep landing on healthy pages while everything that
 * reads the damaged ones fails, so the ingest count stays at zero and the only
 * symptom is a Wanted List that stops growing. That case comes first, because
 * it does not recover by waiting and the user has to act.
 *
 * Deliberately not dismissible. The other banner describes a capability the user
 * may reasonably not want; this one means data is being lost right now, and
 * hiding it would return to exactly the state that caused the problem.
 */
export function HealthBanner() {
  const { t } = useI18n()
  const [health, setHealth] = useState<IngestHealth | null>(null)
  const [storage, setStorage] = useState<StorageHealth | null>(null)

  useEffect(() => {
    let cancelled = false
    const check = async () => {
      try {
        const res = await fetchHealth()
        if (!cancelled) {
          setHealth(res.ingest ?? null)
          setStorage(res.storage ?? null)
        }
      } catch {
        // A failed health check is not itself evidence of a problem: the status
        // bar already reports when the server is unreachable.
      }
    }
    check()
    const stop = visibleInterval(check, 15000)
    return () => { cancelled = true; stop() }
  }, [])

  const damage = storage && !storage.ok ? storage.damage : undefined
  if (damage) {
    // The file name comes from the server, so it is the real one. The folder
    // does not: the health endpoint needs no login, so it never says where
    // the data lives.
    const base = damage.file
    return (
      <div class="banner error" role="alert">
        <span>
          <b>{t.health.damagedTitle}</b>
          <br />
          {fill(t.health.damagedBody, {
            files: `${base}, ${base}-wal, ${base}-shm`,
            error: damage.error,
          })}
        </span>
      </div>
    )
  }

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
