import { useEffect, useState } from 'preact/hooks'
import { Loading } from './loading'
import { fetchSettings, saveSettings, wipeData, fmtBytes, type SettingsData } from './api'
import { useI18n } from './i18n'
import { DispatchPanel } from './dispatch'
import { fetchCaptureInterfaces, type CaptureInterfaces } from './api'

/**
 * Addresses ordered by how much they help someone recognise their own adapter.
 *
 * The list is here so a reader can tell which of a dozen devices is the one
 * their network is on, and macOS returns en0 as fe80::499:847c:8494:9d21 first,
 * with 192.168.1.24 fourth. Only two are shown, so the panel printed two
 * addresses nobody can identify and cut the one everybody knows.
 *
 * Routable IPv4 first because that is the number a person has seen before, then
 * global IPv6, then link-local, which identifies nothing: every interface on
 * the machine has one and they all look alike.
 */
function byRecognisability(addrs: string[]): string[] {
  const rank = (a: string) => {
    const v6 = a.includes(':')
    if (!v6) return a.startsWith('169.254.') ? 2 : 0   // link-local IPv4 is no better than fe80
    return a.toLowerCase().startsWith('fe80') ? 3 : 1
  }
  return [...addrs].sort((x, y) => rank(x) - rank(y))
}

/**
 * Settings, deliberately short. Anything that would need configuring before the
 * tool is useful does not belong here; this is only retention, storage, and the
 * ability to destroy the data.
 */
export function SettingsPanel({ onClose, onWiped }: { onClose: () => void; onWiped: () => void }) {
  const { t } = useI18n()
  const [data, setData] = useState<SettingsData | null>(null)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [confirmWipe, setConfirmWipe] = useState(false)

  useEffect(() => {
    fetchSettings().then(setData).catch(() => setError(t.settings.loadFailed))
  }, [])

  const save = async () => {
    if (!data) return
    setError('')
    try {
      setData(await saveSettings(data))
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e) {
      setError(String((e as Error).message) || t.settings.saveFailed)
    }
  }

  const wipe = async () => {
    try {
      await wipeData()
      setConfirmWipe(false)
      onWiped()
      onClose()
    } catch {
      setError(t.settings.wipeFailed)
    }
  }

  // **Escape closes it.** Clicking the backdrop already did, and a dialog that
  // honours one of those and not the other is a dialog somebody gets stuck in:
  // the keyboard is the way a reader who is not using a mouse leaves, and the
  // close button is a small target in the corner for everyone else. Deliberately
  // not added to the pairing dialogs, which are meant to be hard to dismiss by
  // accident and whose backdrop does not close them either.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div class="modal-backdrop" onClick={onClose}>
      <div class="modal" onClick={(e) => e.stopPropagation()}>
        <div class="modal-head">
          <h2>{t.settings.title}</h2>
          <button class="close" onClick={onClose} title={t.actions.close}>×</button>
        </div>

        {error && <p class="gate-error">{error}</p>}

        {/* An empty dialog is read as broken rather than as pending, which is
            what this one was while its first request was in flight. */}
        {!data && !error && <Loading />}

        {data && (
          <>
            <p class="modal-note">{t.settings.intro}</p>

            <label class="field">
              <span>{t.settings.rawHours}</span>
              <input
                type="number" min="1" max="8760" value={data.retention_raw_hours}
                onInput={(e) => setData({ ...data, retention_raw_hours: +(e.target as HTMLInputElement).value })}
              />
            </label>

            <label class="field">
              <span>{t.settings.rollupDays}</span>
              <input
                type="number" min="1" max="3650" value={data.retention_rollup_days}
                onInput={(e) => setData({ ...data, retention_rollup_days: +(e.target as HTMLInputElement).value })}
              />
            </label>

            <label class="field">
              <span>{t.settings.maxSize}</span>
              <input
                type="number" min="16" value={data.storage_max_mb}
                onInput={(e) => setData({ ...data, storage_max_mb: +(e.target as HTMLInputElement).value })}
              />
            </label>

            <dl class="modal-facts">
              <dt>{t.settings.currentlyUsing}</dt><dd>{fmtBytes(data.db_bytes)}</dd>
              <dt>{t.settings.storedIn}</dt><dd>{data.data_dir}</dd>
            </dl>

            <button class="btn" onClick={save}>{saved ? t.actions.saved : t.actions.save}</button>

            {/* Peering sits above the danger zone: it is ordinary configuration,
                and putting it below a "delete everything" block would bury it. */}
            <CapturePanel />

            <DispatchPanel />

            <div class="danger-zone">
              <h3>{t.settings.dangerTitle}</h3>
              <p>{t.settings.dangerBody}</p>
              {confirmWipe ? (
                <div class="danger-actions">
                  <button class="btn-danger" onClick={wipe}>{t.settings.dangerConfirm}</button>
                  <button class="ghost-btn" onClick={() => setConfirmWipe(false)}>{t.actions.cancel}</button>
                </div>
              ) : (
                <button class="ghost-btn" onClick={() => setConfirmWipe(true)}>{t.settings.dangerButton}</button>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

/** Which network adapter capture is on, and what else it could have picked.
 *
 *  Read-only, deliberately. Knowing what was chosen and what the alternatives
 *  were is the whole diagnostic; changing it means tearing down and reopening a
 *  live capture handle, which is a separate decision with its own failure
 *  modes and needs a way back when the new one turns out to see nothing.
 *
 *  This exists because the automatic pick had no way of being reported. On
 *  Windows every device is named \Device\NPF_{GUID}, the startup log was the
 *  only place the choice appeared, and landing on a virtual adapter with no
 *  traffic looks exactly like a working install on a quiet network. */
function CapturePanel() {
  const { t } = useI18n()
  const [data, setData] = useState<CaptureInterfaces | null>(null)

  useEffect(() => {
    let alive = true
    fetchCaptureInterfaces()
      .then((d) => { if (alive) setData(d) })
      .catch(() => {})
    return () => { alive = false }
  }, [])

  if (!data || !data.available || data.interfaces.length === 0) return null

  return (
    <div class="capture-panel">
      <h3>{t.settings.captureTitle}</h3>
      <p>{t.settings.captureBody}</p>
      <ul class="iface-list">
        {data.interfaces.map((i) => (
          <li key={i.name} class={i.active ? 'active' : ''}>
            <span class="iface-name">{i.description || i.name}</span>
            {i.active && <span class="tag iface-on">{t.settings.captureActive}</span>}
            {!i.active && i.recommended && (
              <span class="tag iface-rec">{t.settings.captureRecommended}</span>
            )}
            <span class="iface-sub">
              {i.description ? i.name : ''}
              {i.addresses && i.addresses.length > 0
                ? `${i.description ? ' \u00b7 ' : ''}${byRecognisability(i.addresses).slice(0, 2).join(', ')}`
                : ''}
            </span>
          </li>
        ))}
      </ul>
      {/* **Reconciles the two tags.**
          The panel could show "in use" on one adapter and "would be chosen
          automatically" on another with nothing to explain how both could be
          true. They are both true precisely when somebody passed --interface,
          and that is the sentence that was missing. */}
      {data.interfaces.some((i) => !i.active && i.recommended) &&
        data.interfaces.some((i) => i.active) && (
          <p class="modal-note">{t.settings.captureOverridden}</p>
        )}
      <p class="modal-note">{t.settings.captureChange}</p>
    </div>
  )
}
