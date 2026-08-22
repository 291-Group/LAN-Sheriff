import { useState } from 'preact/hooks'
import { Badge } from './badge'
import { useI18n, fill } from './i18n'
import { message } from './api'
import { LanguagePicker } from './langpicker'
import type { AuthStatus } from './api'

/**
 * The screen shown before the dashboard: create a password on first run, or
 * sign in on later ones.
 *
 * A password is only ever demanded when the dashboard is reachable from beyond
 * this machine. Bound to localhost there is nothing to protect it from, and
 * this screen never appears.
 */
export function Gate({
  status,
  onDone,
}: {
  status: AuthStatus
  onDone: () => void
}) {
  const { t } = useI18n()
  const setup = status.needs_setup
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: Event) => {
    e.preventDefault()
    setError('')

    if (setup) {
      if (password.length < status.min_password_len) {
        setError(fill(t.gate.tooShort, { min: status.min_password_len }))
        return
      }
      if (password !== confirm) {
        setError(t.gate.mismatch)
        return
      }
    }

    setBusy(true)
    try {
      const res = await fetch(setup ? '/api/auth/setup' : '/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        setError(message(t.msg, body.code, body.error || t.gate.generic))
        return
      }
      onDone()
    } catch {
      setError(t.gate.unreachable)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div class="gate">
      <form class="gate-card" onSubmit={submit}>
        <div class="gate-head">
          <Badge size={34} />
          <div>
            <h1>{setup ? t.gate.setupTitle : t.gate.loginTitle}</h1>
            <small>{t.app.name}</small>
          </div>
        </div>

        {setup ? (
          <p>{status.exposed ? t.gate.setupExposed : t.gate.setupLocal}</p>
        ) : (
          <p>{t.gate.loginPrompt}</p>
        )}

        {error && <p class="gate-error">{error}</p>}
        {status.locked_out && <p class="gate-error">{t.gate.lockedOut}</p>}

        <label class="field">
          <span>{t.gate.password}</span>
          <input
            type="password"
            value={password}
            autoFocus
            autocomplete={setup ? 'new-password' : 'current-password'}
            onInput={(e) => setPassword((e.target as HTMLInputElement).value)}
          />
        </label>

        {setup && (
          <label class="field">
            <span>{t.gate.confirmPassword}</span>
            <input
              type="password"
              value={confirm}
              autocomplete="new-password"
              onInput={(e) => setConfirm((e.target as HTMLInputElement).value)}
            />
          </label>
        )}

        <button class="btn" type="submit" disabled={busy || !password}>
          {busy ? t.gate.working : setup ? t.gate.submitSetup : t.gate.submitLogin}
        </button>

        {setup && (
          <p class="gate-note">{t.gate.storedAs}</p>
        )}

        <div class="gate-foot">
          <p class="motto">&ldquo;{t.app.motto}&rdquo;</p>

          {/* **The one screen with no other way to identify itself.**
              Everything else can read the version from the dashboard footer,
              but a person sitting at a login box cannot reach the dashboard by
              definition, and a bug report from here was otherwise
              unattributable to a build. The version comes from /api/auth/status,
              which is the only endpoint served before signing in.

              rel="noreferrer" so the local address is not sent to GitHub, which
              on a private network is nobody's business.

              It links to the organisation rather than to this repository. From a
              login box the useful question is "who are these people", and the
              org page answers it and leads to the repository anyway. */}
          {/* bdi, because this line is the one place a Latin product name, a
              Latin version and a number sit together inside a paragraph that may
              be right to left. Without isolation the bidi algorithm detaches the
              number and moves it: in Arabic this rendered as "122 build LAN
              Sheriff v0.9.8b", which names the wrong build to the reader who has
              the least other way to check. */}
          <p class="gate-version">
            <bdi>
              {t.app.name} {status.version}
              {status.build && <> {fill(t.app.build, { n: status.build })}</>}
            </bdi>
          </p>
          <p class="built-by">{t.app.byOrg}</p>

          <p class="gate-link">
            <a
              href="https://github.com/291-Group"
              target="_blank"
              rel="noreferrer noopener"
            >GitHub.com/291-Group</a>
          </p>
          <p class="gate-link">
            <a
              href="https://LANSheriff.com"
              target="_blank"
              rel="noreferrer noopener"
            >LANSheriff.com</a>
          </p>

          <LanguagePicker compact />
        </div>
      </form>
    </div>
  )
}
