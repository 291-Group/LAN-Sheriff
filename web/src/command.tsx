import { useState } from 'preact/hooks'
import { useI18n } from './i18n'

/**
 * A shell command for the user to run, with click-to-copy.
 *
 * Deliberately not a button that does something. LAN Sheriff cannot run this on
 * its own behalf, enabling packet capture means rebuilding with libpcap, or
 * granting privileges to the binary, so presenting it as an action would be a
 * lie. What the app can honestly do is save you retyping it.
 */
export function Command({ cmd }: { cmd: string }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(cmd)
    } catch {
      // Clipboard access is refused on insecure origins and in some browsers.
      // Fall back to selecting the text so the user can copy it by hand.
      const el = document.getElementById(`cmd-${slug(cmd)}`)
      if (el) {
        const range = document.createRange()
        range.selectNodeContents(el)
        getSelection()?.removeAllRanges()
        getSelection()?.addRange(range)
      }
      return
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 1600)
  }

  return (
    <span class="command">
      <span class="command-label">{t.actions.runThis}</span>
      <code id={`cmd-${slug(cmd)}`}>{cmd}</code>
      <button class="command-copy" onClick={copy} title={t.actions.copy}>
        {copied ? t.actions.copied : t.actions.copy}
      </button>
    </span>
  )
}

function slug(s: string): string {
  return s.replace(/[^a-z0-9]+/gi, '-').toLowerCase()
}
