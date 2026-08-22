import { useEffect, useRef, useState } from 'preact/hooks'
import { useI18n, LANGUAGES, type Lang } from './i18n'

/**
 * Language picker.
 *
 * Each language is listed in its own script, because someone looking for their
 * language is scanning for how it looks, not for its English name. The English
 * name follows as a subtitle so the list stays navigable to everyone else.
 */
// **Every button here declares type="button".**
//
// A <button> with no type is a submit button, and this picker is rendered
// inside the sign-in form. Clicking the language name submitted the form with
// an empty password, so the screen answered "incorrect password" to somebody
// who had typed nothing and pressed nothing resembling a submit. Reported from
// the login screen, where it is at its most alarming.
export function LanguagePicker({ compact = false }: { compact?: boolean }) {
  const { lang, setLang, t } = useI18n()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])

  const current = LANGUAGES.find((l) => l.id === lang) ?? LANGUAGES[0]

  return (
    <div class={`langpicker ${compact ? 'compact' : ''}`} ref={ref}>
      <button type="button"
        class={compact ? 'lang-link' : 'icon-btn lang-btn'}
        title={t.actions.language}
        aria-label={t.actions.language}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {compact ? current.native : '文A'}
      </button>

      {open && (
        <div class="lang-menu" role="listbox">
          {LANGUAGES.map((l) => (
            <button type="button"
              key={l.id}
              role="option"
              aria-selected={l.id === lang}
              class={`lang-option ${l.id === lang ? 'on' : ''}`}
              onClick={() => { setLang(l.id as Lang); setOpen(false) }}
            >
              <span class="lang-native">{l.native}</span>
              <span class="lang-english">{l.english}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
