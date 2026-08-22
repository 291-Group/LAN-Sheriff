import { useEffect, useRef } from 'preact/hooks'

/** Whether the page is on screen. A tab in the background, a minimised window
 *  and a locked screen all report hidden. */
export function pageVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState !== 'hidden'
}

/**
 * The plain-function form, for the many polls that already live inside a
 * useEffect and return their own cleanup. Returns a stop function, so it is a
 * direct swap for `setInterval` plus `clearInterval` without restructuring the
 * component around a hook.
 *
 * Same behaviour as the hook below: nothing fires while the page is off screen,
 * and returning to the tab runs the callback once immediately so the user is
 * never looking at data that quietly stopped updating.
 */
export function visibleInterval(fn: () => void, intervalMs: number): () => void {
  let timer: number | undefined

  const start = () => {
    if (timer === undefined) timer = window.setInterval(fn, intervalMs)
  }
  const stop = () => {
    if (timer !== undefined) {
      window.clearInterval(timer)
      timer = undefined
    }
  }
  const onVisibility = () => {
    if (pageVisible()) {
      fn()
      start()
    } else {
      stop()
    }
  }

  if (pageVisible()) start()
  document.addEventListener('visibilitychange', onVisibility)
  return () => {
    stop()
    document.removeEventListener('visibilitychange', onVisibility)
  }
}

/**
 * setInterval that stops while the page is not on screen, and catches up the
 * moment it comes back.
 *
 * The dashboard had seven independent polling timers and every one of them kept
 * firing for a page nobody was looking at: fetching, parsing, diffing and
 * re-rendering into a hidden document. Browsers already throttle animation
 * frames in a background tab, which is why the map goes quiet on its own, but
 * they do not stop timers, so the rest carried on indefinitely.
 *
 * This needs no measurement to justify, which matters, because the measurements
 * this was nearly justified with turned out to have been taken on a loaded
 * machine and were worthless. Doing work for a page nobody can see is waste
 * whatever a profiler says, and a network monitor spends most of its life in a
 * tab somebody left open.
 *
 * The immediate run on returning is the part that keeps it honest: a user who
 * comes back to the tab must not be shown data that quietly stopped updating
 * while they were away. They see one refresh, not a gap.
 */
export function useVisibleInterval(fn: () => void, intervalMs: number) {
  const saved = useRef(fn)
  saved.current = fn

  useEffect(() => {
    let timer: number | undefined

    const start = () => {
      if (timer !== undefined) return
      timer = window.setInterval(() => saved.current(), intervalMs)
    }
    const stop = () => {
      if (timer === undefined) return
      window.clearInterval(timer)
      timer = undefined
    }

    const onVisibility = () => {
      if (pageVisible()) {
        // Catch up first, then resume the schedule, so the interval is not
        // spent showing stale data.
        saved.current()
        start()
      } else {
        stop()
      }
    }

    if (pageVisible()) start()
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      stop()
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [intervalMs])
}
