import { useEffect, useRef, useState } from 'preact/hooks'
import { fetchTimeline, type Filter, type TimePoint } from './api'
import { useI18n } from './i18n'
import { visibleInterval } from './visibility'

/**
 * The scrub control: hourly activity across the selected range, with a window
 * you can drag to look at the past.
 *
 * Drawn on a canvas rather than as hundreds of elements, because a 30-day range
 * is 720 bars and this sits under a map that is already animating.
 */
export function Timeline({
  filter, onChange,
}: {
  filter: Filter
  onChange: (f: Filter) => void
}) {
  const { t } = useI18n()
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const [points, setPoints] = useState<TimePoint[]>([])
  const [hover, setHover] = useState<number | null>(null)

  // Reload when the range changes, and refresh periodically while live.
  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const r = await fetchTimeline({ ...filter, from: undefined, to: undefined })
        if (!cancelled) setPoints(r.points)
      } catch {
        if (!cancelled) setPoints([])
      }
    }
    load()
    if (filter.from) return () => { cancelled = true }
    const stop = visibleInterval(load, 30_000)
    return () => { cancelled = true; stop() }
  }, [filter.range, filter.from])

  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if (!canvas || !wrap) return

    const draw = () => {
      const cs = getComputedStyle(document.documentElement)
      const v = (n: string, f: string) => cs.getPropertyValue(n).trim() || f
      const { width, height } = wrap.getBoundingClientRect()
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      canvas.width = Math.round(width * dpr)
      canvas.height = Math.round(height * dpr)
      const ctx = canvas.getContext('2d')
      if (!ctx) return
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, width, height)

      if (points.length === 0) return

      const peak = Math.max(...points.map((p) => p.conns), 1)
      const slot = width / points.length
      const barW = Math.max(1, slot - 1)

      const selFrom = filter.from
      const selTo = filter.to ?? Math.floor(Date.now() / 1000)

      points.forEach((p, i) => {
        const h = Math.max(p.conns > 0 ? 2 : 0, (p.conns / peak) * (height - 6))
        const x = i * slot
        // An hour inside the scrubbed window is highlighted; the rest recedes.
        const inWindow = !selFrom || (p.ts >= selFrom && p.ts <= selTo)
        ctx.fillStyle = inWindow ? v('--calm', '#2f7fd4') : v('--arc-idle', '#adb9c9')
        ctx.globalAlpha = i === hover ? 1 : inWindow ? 0.75 : 0.3
        ctx.fillRect(x, height - h - 3, barW, h)
      })
      ctx.globalAlpha = 1
    }

    draw()
    const ro = new ResizeObserver(draw)
    ro.observe(wrap)
    // The bars are themed, so they must be redrawn when the theme changes.
    const mo = new MutationObserver(draw)
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => { ro.disconnect(); mo.disconnect() }
  }, [points, hover, filter.from, filter.to])

  const hourAt = (clientX: number): TimePoint | null => {
    const wrap = wrapRef.current
    if (!wrap || points.length === 0) return null
    const r = wrap.getBoundingClientRect()
    const i = Math.floor(((clientX - r.left) / r.width) * points.length)
    return points[Math.min(Math.max(i, 0), points.length - 1)] ?? null
  }

  if (points.length === 0) return null

  const total = points.reduce((sum, p) => sum + p.conns, 0)

  return (
    <div class="timeline">
      <div
        class="timeline-bars"
        ref={wrapRef}
        title={t.timeline.hint}
        onMouseMove={(e) => {
          const p = hourAt(e.clientX)
          setHover(p ? points.indexOf(p) : null)
        }}
        onMouseLeave={() => setHover(null)}
        onClick={(e) => {
          const p = hourAt(e.clientX)
          if (!p) return
          // Clicking an hour pins the view to that hour.
          onChange({ ...filter, from: p.ts, to: p.ts + 3600 })
        }}
      >
        <canvas ref={canvasRef} />
      </div>

      <div class="timeline-foot">
        <span>{fmtHour(points[0]?.ts)}</span>
        {hover !== null && points[hover] ? (
          <span class="timeline-read">
            {fmtHour(points[hover].ts)} · {points[hover].conns}
          </span>
        ) : (
          <span class="timeline-read">{total} {t.timeline.inRange}</span>
        )}
        {filter.from ? (
          <button
            class="timeline-live"
            onClick={() => onChange({ ...filter, from: undefined, to: undefined })}
          >
            {t.toolbar.backToLive}
          </button>
        ) : (
          <span>{t.timeline.now}</span>
        )}
      </div>
    </div>
  )
}

function fmtHour(ts?: number): string {
  if (!ts) return ''
  const d = new Date(ts * 1000)
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric' })
}
