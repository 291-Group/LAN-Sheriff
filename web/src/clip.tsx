import { useState } from 'preact/hooks'
import { useI18n } from './i18n'

/**
 * Copy and paste for the pairing screens.
 *
 * # Why these are not one-liners around navigator.clipboard
 *
 * The clipboard API is only available in a **secure context**, which means
 * https or localhost. LAN Sheriff is served over plain http, so on the machine
 * itself (127.0.0.1) the API exists, and on `http://192.168.1.31:2911` from
 * another machine it does not exist at all. That is exactly the case pairing
 * happens in: somebody reading a code off a machine across the room.
 *
 * So Copy falls back to selecting the text, which is what the existing Command
 * button already does, and Paste hides itself entirely where it cannot work
 * rather than sitting there failing. A button that does nothing when pressed is
 * worse than no button, and this is the one screen where a person is already
 * unsure whether the software is broken.
 */
export function CopyButton({ value, class: cls }: { value: string; class?: string }) {
  const { t } = useI18n()
  const [done, setDone] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setDone(true)
      setTimeout(() => setDone(false), 1600)
    } catch {
      // Insecure origin, or permission refused. Select the text so it can be
      // copied by hand rather than pretending the click did something.
      const el = document.getElementById(`clip-${slug(value)}`)
      if (el) {
        const r = document.createRange()
        r.selectNodeContents(el)
        getSelection()?.removeAllRanges()
        getSelection()?.addRange(r)
      }
    }
  }

  return (
    <button type="button" class={`clip-btn ${cls ?? ''}`} onClick={copy} title={t.actions.copy}>
      {done ? t.actions.copied : t.actions.copy}
    </button>
  )
}

/** True when the browser will actually let us read the clipboard. */
export function canPaste(): boolean {
  return typeof navigator !== 'undefined' &&
    !!navigator.clipboard &&
    typeof navigator.clipboard.readText === 'function'
}

export function PasteButton({ onPaste }: { onPaste: (text: string) => void }) {
  const { t } = useI18n()
  const [failed, setFailed] = useState(false)
  if (!canPaste()) return null

  const paste = async () => {
    try {
      onPaste(await navigator.clipboard.readText())
      setFailed(false)
    } catch {
      // Firefox refuses readText outright, and Chrome asks. Either way, say so
      // rather than leaving the field empty with no explanation.
      setFailed(true)
    }
  }

  return (
    <button type="button" class="clip-btn" onClick={paste} title={t.actions.paste}>
      {failed ? t.actions.pasteBlocked : t.actions.paste}
    </button>
  )
}

export function slug(s: string): string {
  return s.replace(/[^a-z0-9]+/gi, '-').toLowerCase()
}
