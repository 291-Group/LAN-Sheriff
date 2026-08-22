import { useEffect, useState } from 'preact/hooks'
import { useI18n } from './i18n'

/**
 * A loading indicator that waits before it appears.
 *
 * # Why the delay
 *
 * The rest of this product deliberately shows nothing while a request is in
 * flight, and the reasoning beside `.chatter-loading` is right: these calls are
 * local and usually finish inside a frame or two, so a spinner that appears and
 * vanishes that fast is itself a flicker.
 *
 * That reasoning holds for a region of a page that is already on screen. It
 * does not hold for a dialog, which arrives as a new surface with nothing on
 * it: an empty modal is not read as "one moment", it is read as broken, and it
 * was. `/api/settings` answers in about 20ms on this machine, and much slower
 * on a Raspberry Pi with a large database, over a network, or on the first call
 * after the process starts.
 *
 * So: nothing at all for `delay` milliseconds, which covers every fast case
 * with no flicker, then an indicator for the slow ones. The two concerns turn
 * out not to be in conflict; the original code just picked one of them.
 */
export function Loading({ delay = 180 }: { delay?: number }) {
  const { t } = useI18n()
  const [show, setShow] = useState(false)

  useEffect(() => {
    const id = setTimeout(() => setShow(true), delay)
    return () => clearTimeout(id)
  }, [delay])

  // Rendered either way so the box keeps its height and the dialog does not
  // resize under the reader's cursor when the content arrives.
  return (
    <div class="loading" role="status" aria-busy="true" aria-live="polite">
      {show && (
        <>
          <span class="loading-spin" aria-hidden="true" />
          <span class="loading-label">{t.actions.loading}</span>
        </>
      )}
    </div>
  )
}
