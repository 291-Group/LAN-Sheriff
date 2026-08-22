// The Watchtower's rendering core: a world map on a canvas with animated
// great-circle arcs out to every destination.
//
// Canvas rather than SVG, and plain d3-geo rather than a mapping library,
// because this has to stay smooth on a Raspberry Pi with several hundred live
// arcs.

import { geoNaturalEarth1, geoPath, geoInterpolate, geoCentroid, type GeoProjection } from 'd3-geo'
import { feature, mesh } from 'topojson-client'
import landTopo from 'world-atlas/land-110m.json'
import type { Origin } from './api'

const land = feature(landTopo as never, (landTopo as never as any).objects.land) as never

/**
 * Pulse pacing. These are the numbers to change if the animation feels wrong.
 *
 * Every pulse crosses its arc in between MIN and MAX seconds, whatever the
 * arc's length. Keeping that window narrow is what makes the map read as one
 * system rather than a collection of independently-timed animations.
 *
 * The two failure modes this sits between: constant pixel speed, where a long
 * arc appears stalled because it takes a minute to cross, and constant
 * duration, where long arcs visibly race to finish alongside short ones.
 */
const PULSE_MIN_SECONDS = 4.5
const PULSE_MAX_SECONDS = 8
/** Arc length, in pixels, that should land near the middle of that range. */
const PULSE_REFERENCE_PX = 600

/**
 * What the map needs in order to draw something, and nothing more.
 *
 * Introduced when peer destinations arrived. A peer reports an organization and
 * a country and **deliberately no address**, so it cannot be an `Endpoint`, and
 * synthesising a fake IP to make it fit would be exactly the conflation the
 * store comment warns against. Instead both shapes are adapted to this at the
 * call site, and the renderer knows about neither.
 */
export interface Drawable {
  /** Identity, for reusing arc phases across refreshes and for selection. */
  key: string
  lat?: number
  lon?: number
  is_internal?: boolean
  /** Drives arc thickness. */
  conns: number
  active?: boolean
  /** Unix seconds; drives the "just now" colour. */
  last_flow?: number
  /** Tooltip. */
  title: string
  place?: string
  who?: string
  /** Reported by a paired machine rather than observed here. Drawn in its own
      colour, because on the Everything layer your own closed connections and a
      peer's reports are on screen together and were indistinguishable. */
  peer?: boolean
}

export interface Arc {
  ep: Drawable
  /** Sample points along the great circle, in [lon, lat]. */
  points: [number, number][]

  // Screen-space geometry, computed once per projection change rather than per
  // frame. Re-projecting every arc on every frame is the difference between
  // this being smooth on a Pi and not running at all.
  /** Projected polyline, pre-split where it would wrap the antimeridian. */
  segments: [number, number][][]
  /** Flattened projected points, for positioning the travelling pulse. */
  flat: [number, number][]
  /** Cumulative screen-space distance to each point in `flat`. */
  cum: number[]
  /** Total drawn length in pixels. */
  length: number
  /** Projected destination, or null if it falls off the projection. */
  dot: [number, number] | null

  /** 0..1 position of the travelling pulse. */
  phase: number
  speed: number
  weight: number
  colour: string
}

/**
 * Map colours come from the stylesheet rather than being hardcoded, so the
 * canvas follows the theme toggle instead of disagreeing with the chrome
 * around it. Read once per theme change and cached, a getComputedStyle call
 * per frame would be a needless cost on a Pi.
 */
type Palette = {
  ocean: string; land: string; landEdge: string; origin: string
  calm: string; warm: string; hot: string; idle: string
  tooltipBg: string; tooltipEdge: string; text: string; textDim: string
  peer: string
}

function readPalette(): Palette {
  const s = getComputedStyle(document.documentElement)
  const v = (name: string, fallback: string) => s.getPropertyValue(name).trim() || fallback
  return {
    ocean: v('--map-ocean', 'rgba(255,255,255,0.4)'),
    land: v('--map-land', '#d6dfeb'),
    landEdge: v('--map-edge', '#c2cedd'),
    origin: v('--star', '#d9a227'),
    calm: v('--calm', '#2f7fd4'),
    warm: v('--warm', '#e0842c'),
    hot: v('--hot', '#d9483f'),
    idle: v('--arc-idle', '#adb9c9'),
    peer: v('--arc-peer', '#8b6fc4'),
    tooltipBg: v('--map-tooltip-bg', 'rgba(255,255,255,0.94)'),
    tooltipEdge: v('--map-tooltip-edge', 'rgba(16,24,40,0.12)'),
    text: v('--text', '#16202e'),
    textDim: v('--text-dim', '#56637a'),
  }
}

/**
 * Arc colour by how much attention the destination deserves. This is honest
 * about what it actually knows: recency and whether the endpoint is still
 * active, rather than a risk score it cannot compute.
 */
function arcColour(e: Drawable, col: Palette): string {
  // Checked before anything else: a peer's report is not this machine's
  // observation, and saying so is the whole point of the Everything layer.
  if (e.peer) return col.peer
  if (!e.active) return col.idle
  const age = Date.now() / 1000 - (e.last_flow ?? 0)
  if (age < 20) return col.warm
  return col.calm
}

export class Watchtower {
  private ctx: CanvasRenderingContext2D
  private projection: GeoProjection
  private path: ReturnType<typeof geoPath>
  private raf = 0
  private arcs: Arc[] = []
  private origin: Origin | null = null
  private width = 0
  private height = 0
  private dpr = 1
  private hover: Arc | null = null
  private selectedIP: string | null = null
  private col: Palette = readPalette()
  private themeObserver: MutationObserver | null = null

  /** The fitted view, captured after every fitExtent.
   *
   *  Zooming is expressed relative to this rather than by re-fitting, because
   *  the fitted view is the floor: `k` never goes below 1, so the map can never
   *  be smaller than the frame it lives in and there is no state in which the
   *  reader is looking at a postage stamp with dead space around it. */
  private baseScale = 1
  private baseTranslate: [number, number] = [0, 0]
  private baseBounds: [[number, number], [number, number]] = [[0, 0], [0, 0]]

  /** Scale multiple over the fitted view. 1 is fully zoomed out. */
  private k = 1

  /** Dragging state. `moved` exists to tell a drag from a click: without it,
   *  releasing the mouse after panning also selected whatever was underneath. */
  private dragging = false
  private moved = 0
  private dragFrom: [number, number] = [0, 0]

  /** The ocean, the landmasses, and every arc that is not currently moving,
   *  drawn once and copied thereafter.
   *
   *  The basemap was being rebuilt on **every animation frame**: `path(land)`
   *  runs the Natural Earth coastlines through the projection and tessellates
   *  them, sixty times a second, to produce an image identical to the one
   *  already on screen. Everything that actually moves, the arcs and their
   *  pulses, is a rounding error beside it.
   *
   *  The arcs went in for the same reason, one report later. Only an *active*
   *  endpoint carries a travelling pulse; an idle one is a static line that was
   *  being re-stroked sixty times a second along with all the others. The map
   *  draws up to 500 endpoints at 25 points each, so a dashboard left open on a
   *  busy network worked its way up to 12,500 lineTo calls per frame, which is
   *  750,000 a second. That is why the cost **crept up** rather than being bad
   *  from the start: it scales with how many places the machine has talked to.
   *
   *  Invalidated by a resize, a theme change, new data, and a change of
   *  selection. The first two are rare and the last two happen every few
   *  seconds, which against sixty frames a second is nothing. */
  private basemap: HTMLCanvasElement | null = null

  /**
   * Country borders and names, off unless asked for.
   *
   * The geometry is a separate 108 KB file, fetched the first time the control
   * is switched on rather than bundled, because most readers never turn it on
   * and it is a third the size of everything else the dashboard ships. Until it
   * arrives the map draws exactly as before, so switching on is never a blank
   * screen, only a map that gains borders a moment later.
   */
  private borders: { mesh: unknown; labels: Array<{ name: string; at: [number, number] }> } | null = null
  private showCountries = false

  /** True once a still frame has been drawn and there is nothing left moving.
   *  Cleared by anything that changes what the canvas should show, so a quiet
   *  map still repaints when the data, the theme, the size or the selection
   *  changes. */
  private settled = false

  onSelect: (ip: string | null) => void = () => {}

  constructor(private canvas: HTMLCanvasElement) {
    const ctx = canvas.getContext('2d', { alpha: true })
    if (!ctx) throw new Error('canvas 2d unavailable')
    this.ctx = ctx
    this.projection = geoNaturalEarth1()
    this.path = geoPath(this.projection, ctx)

    canvas.addEventListener('mousemove', this.onMove)
    canvas.addEventListener('mouseleave', this.onLeave)
    canvas.addEventListener('click', this.onClick)
    // Not passive: the page must not scroll while the pointer is over the map.
    canvas.addEventListener('wheel', this.onWheel, { passive: false })
    canvas.addEventListener('mousedown', this.onDown)
    window.addEventListener('mousemove', this.onDrag)
    window.addEventListener('mouseup', this.onUp)

    // Watch the theme attribute directly rather than waiting to be told.
    //
    // A observer callback runs as a microtask, before the next animation frame,
    // so the canvas adopts the new palette in the same tick the CSS changes.
    // Driving this from a component effect instead leaves the map painting one
    // or more frames in the old colours against the new background, which reads
    // as a flash of the opposite theme.
    this.themeObserver = new MutationObserver(() => this.refreshTheme())
    this.themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    })
  }

  /** Re-reads the palette after a theme change and recolours existing arcs. */
  refreshTheme() {
    this.col = readPalette()
    this.basemap = null // different colours, different basemap
    this.settled = false
    for (const a of this.arcs) a.colour = arcColour(a.ep, this.col)
    // Paint now rather than waiting for the scheduled frame, so there is no
    // window in which the old colours are still on screen.
    this.draw()
  }

  destroy() {
    cancelAnimationFrame(this.raf)
    this.themeObserver?.disconnect()
    this.themeObserver = null
    this.canvas.removeEventListener('mousemove', this.onMove)
    this.canvas.removeEventListener('mouseleave', this.onLeave)
    this.canvas.removeEventListener('click', this.onClick)
    this.canvas.removeEventListener('wheel', this.onWheel)
    this.canvas.removeEventListener('mousedown', this.onDown)
    // Bound to the window rather than the canvas, so a drag that leaves the
    // map still ends when the button is released.
    window.removeEventListener('mousemove', this.onDrag)
    window.removeEventListener('mouseup', this.onUp)
  }

  resize(w: number, h: number) {
    this.basemap = null // different size, different basemap
    this.settled = false
    this.dpr = Math.min(window.devicePixelRatio || 1, 2)
    this.width = w
    this.height = h
    this.canvas.width = Math.round(w * this.dpr)
    this.canvas.height = Math.round(h * this.dpr)
    this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0)
    this.projection.fitExtent(
      [
        [10, 14],
        [w - 10, h - 14],
      ],
      land,
    )
    // The floor, captured before any zoom is applied on top of it.
    //
    // fitExtent centres the land in an extent whose own centre is the middle of
    // the canvas, so at k = 1 the clamp below reproduces this translate exactly.
    // That is what makes "fully zoomed out" and "the view we shipped" the same
    // thing rather than merely similar.
    this.baseScale = this.projection.scale()
    this.baseTranslate = this.projection.translate() as [number, number]
    this.baseBounds = this.path.bounds(land) as [[number, number], [number, number]]

    // Keep the zoom across a resize, anchored on the middle of the frame.
    // Re-fitting would silently throw the reader back out to the whole world
    // because a sidebar opened.
    const c: [number, number] = [w / 2, h / 2]
    this.applyView(
      [c[0] - this.k * (c[0] - this.baseTranslate[0]),
       c[1] - this.k * (c[1] - this.baseTranslate[1])],
      this.k,
    )
  }

  /** How far in the map is: 1 is fully out, and is the floor. */
  get zoom(): number { return this.k }

  /** Reports every change, so a control can dim itself at the limits. */
  onZoom: (k: number, min: boolean, max: boolean) => void = () => {}

  /** The furthest in the map will go.
   *
   *  Eight, because the projection is a fixed raster of coastlines rather than
   *  tiles: past this the outlines are visibly soft and zooming further buys
   *  nothing but a blurrier picture. */
  static readonly MAX_ZOOM = 8

  /** Multiplies the zoom, holding one screen point still.
   *
   *  Holding the pointer still is what makes wheel zoom feel like zooming
   *  rather than like the map jumping: the country under the cursor stays under
   *  the cursor. The buttons pass no focus and so zoom about the middle. */
  zoomBy(factor: number, focus?: [number, number]) {
    let k = Math.min(Watchtower.MAX_ZOOM, Math.max(1, this.k * factor))
    // Snap to the limits. Two steps in and two steps out is 1.6 * 1.6 / 1.6 /
    // 1.6, which in binary floating point is 1.0000000000000002 rather than 1.
    // The difference is invisible on the map and very visible on the control:
    // the zoom-out button stayed lit at the floor, so it looked broken, and the
    // view never quite returned to the fitted one it started from.
    if (k < 1.0001) k = 1
    if (k > Watchtower.MAX_ZOOM - 0.0001) k = Watchtower.MAX_ZOOM
    if (k === this.k) return
    const t = this.projection.translate() as [number, number]
    // The buttons pass no focus, and the middle of the frame is the wrong
    // default: on this projection that is the Atlantic, so pressing + walked
    // the reader into empty ocean while every arc they own ran off the top
    // corner. Zoom towards home instead, which is where the arcs begin.
    const f = focus ?? this.originPoint() ?? [this.width / 2, this.height / 2]
    const r = k / this.k
    this.applyView([f[0] + r * (t[0] - f[0]), f[1] + r * (t[1] - f[1])], k)
  }

  /** Where this network sits on screen, if it is known yet. */
  private originPoint(): [number, number] | null {
    if (!this.origin?.known) return null
    return (this.projection([this.origin.lon, this.origin.lat]) as [number, number]) ?? null
  }

  /** Back to the fitted view. */
  resetZoom() {
    if (this.k === 1) return
    this.applyView(this.baseTranslate, 1)
  }

  /** Installs a scale and an offset, clamped, and invalidates what they change.
   *
   *  Everything projected is cached: the basemap is a bitmap and the arcs are
   *  screen-space points. Both are wrong the instant the projection moves, so
   *  both are dropped here rather than at each call site, which is where one of
   *  them would eventually be forgotten. */
  private applyView(t: [number, number], k: number) {
    this.k = k
    this.projection.scale(this.baseScale * k).translate(this.clamp(t, k))
    this.basemap = null
    this.settled = false
    this.project()
    this.onZoom(k, k <= 1, k >= Watchtower.MAX_ZOOM)
  }

  /** Keeps the world covering the frame, so there is no dragging off into grey.
   *
   *  A projected point moves linearly with the view: scaling by k about the
   *  fitted translate sends p to t + k(p - baseTranslate). So the drawn bounds
   *  can be derived from the fitted ones arithmetically, and no geometry has to
   *  be walked on every frame of a drag. */
  private clamp(t: [number, number], k: number): [number, number] {
    const [[x0, y0], [x1, y1]] = this.baseBounds
    const [bx, by] = this.baseTranslate
    const axis = (
      lo: number, hi: number, base: number, want: number, extent: number,
    ): number => {
      const a = k * (lo - base)
      const b = k * (hi - base)
      // Narrower than the frame: centred, with nothing to choose. This is the
      // case at k = 1, which is why fully zoomed out lands back exactly.
      if (b - a <= extent) return extent / 2 - (a + b) / 2
      return Math.min(-a, Math.max(extent - b, want))
    }
    return [
      axis(x0, x1, bx, t[0], this.width),
      axis(y0, y1, by, t[1], this.height),
    ]
  }

  setSelected(ip: string | null) {
    this.basemap = null // the selected arc moves out of the cache and back in
    this.settled = false
    this.selectedIP = ip
  }

  /** Replaces the drawn set. Arc phases are preserved so the animation does not
   *  jump every time the data refreshes. */
  setData(origin: Origin, endpoints: Drawable[]) {
    this.basemap = null // different arcs, different cached layer
    this.settled = false
    this.origin = origin
    const previous = new Map(this.arcs.map((a) => [a.ep.key, a]))
    const from: [number, number] = origin.known ? [origin.lon, origin.lat] : [0, 20]

    this.arcs = endpoints
      .filter((e) => (e.lat || e.lon) && !e.is_internal)
      .map((e) => {
        const to: [number, number] = [e.lon!, e.lat!]
        const prev = previous.get(e.key)
        const interp = geoInterpolate(from, to)
        // 24 samples is plenty for a smooth great circle at this scale and
        // keeps the per-frame path cost low.
        const points: [number, number][] = []
        for (let i = 0; i <= 24; i++) points.push(interp(i / 24) as [number, number])

        return {
          ep: e,
          points,
          segments: [],
          flat: [],
          cum: [],
          length: 0,
          dot: null,
          phase: prev?.phase ?? Math.random(),
          // Set in project(), once the arc's drawn length is known.
          speed: 0,
          weight: Math.min(2.6, 0.55 + Math.log10(1 + e.conns) * 0.9),
          colour: arcColour(e, this.col),
        }
      })

    this.project()
  }

  /**
   * Projects every arc into screen space. Called when the data or the
   * projection changes, never from the draw loop.
   */
  private project() {
    for (const a of this.arcs) {
      const pts: [number, number][] = []
      for (const p of a.points) {
        const xy = this.projection(p)
        if (xy) pts.push(xy as [number, number])
      }
      a.flat = pts

      // Measure the arc in screen pixels, not in samples.
      //
      // The samples are evenly spaced in great-circle angle, but the projection
      // stretches and compresses that unevenly across the map. Stepping the
      // pulse by sample index therefore moves it at a visibly varying speed, 
      // worst on long arcs, which cross the most distortion. Walking cumulative
      // screen distance instead gives constant apparent speed.
      const cum: number[] = new Array(pts.length)
      let total = 0
      cum[0] = 0
      for (let i = 1; i < pts.length; i++) {
        const dx = pts[i][0] - pts[i - 1][0]
        const dy = pts[i][1] - pts[i - 1][1]
        // A wrap across the antimeridian is a discontinuity, not travel: count
        // it as zero so the pulse does not stall while "crossing" it.
        const step = Math.abs(dx) > this.width * 0.5 ? 0 : Math.hypot(dx, dy)
        total += step
        cum[i] = total
      }
      a.cum = cum
      a.length = total

      // Choose a traversal *time*, then derive the speed from it.
      //
      // Constant pixel speed is physically consistent but looks wrong: a short
      // hop finishes in a couple of seconds while a trans-Pacific arc takes the
      // better part of a minute, and the long one reads as stalled. Constant
      // duration is the other extreme, every dot lands together, so long arcs
      // visibly race. Scaling duration by the square root of length splits the
      // difference: a sixteen-times-longer arc takes four times as long rather
      // than sixteen, and both ends stay in a range that looks deliberate.
      const raw = Math.sqrt(Math.max(total, 1) / PULSE_REFERENCE_PX) * 5.5
      const seconds = Math.min(Math.max(raw, PULSE_MIN_SECONDS), PULSE_MAX_SECONDS)
      // No per-endpoint speed variation. Busier destinations are already shown
      // by arc thickness, and varying the pace as well made the map look
      // unsettled rather than informative.
      a.speed = total > 0 ? total / seconds : 0

      // A projected great circle can wrap the antimeridian and streak across
      // the whole map; splitting on implausible jumps keeps that off screen.
      const segments: [number, number][][] = []
      let current: [number, number][] = []
      for (let i = 0; i < pts.length; i++) {
        if (i > 0 && Math.abs(pts[i][0] - pts[i - 1][0]) > this.width * 0.5) {
          if (current.length > 1) segments.push(current)
          current = []
        }
        current.push(pts[i])
      }
      if (current.length > 1) segments.push(current)
      a.segments = segments

      a.dot = (this.projection([a.ep.lon!, a.ep.lat!]) as [number, number]) ?? null
    }
  }

  start() {
    // **Thirty frames a second, and none at all when nothing is moving.**
    //
    // Profiling the running dashboard, rather than timing one function and
    // guessing, put 30% of the Watchtower's cost in the browser's own paint and
    // composite work and only a few percent in our drawing code. Caching the
    // geometry made each frame cheap; it could not make a frame free, because
    // presenting a full-canvas image has a floor. The only lever left is asking
    // for fewer of them.
    //
    // **No frame-rate cap.** One was added here and then removed: halving the
    // rate is a visible change to how the map moves, and the measurement that
    // was supposed to justify it turned out to have been taken on a machine
    // running at a load average of four, with a browser doing real work beside
    // it. The spread across identical runs was 10.9% to 93.3% of a core, so
    // nothing measured in that state could support a product change. A cost
    // that cannot be demonstrated does not get paid for in smoothness.
    //
    // What remains needs no measurement to justify. The idle case: A pulse only exists on an *active*
    // endpoint, so a map with nothing live has nothing to animate and every
    // frame it draws is identical to the last. Those frames are now skipped
    // entirely: the canvas keeps its content, the loop keeps ticking cheaply,
    // and the cost falls to nothing until traffic arrives. A monitor spends
    // most of its life being left open on a quiet network, so this is the
    // common case rather than an optimisation for an unusual one.
    let last = performance.now()
    const tick = (now: number) => {
      this.raf = requestAnimationFrame(tick)
      // Advance by measured elapsed time rather than assuming a fixed frame
      // interval. A hardcoded step makes the pulses speed up and slow down with
      // the frame rate, which reads as judder even when nothing is dropping.
      // Clamped so a tab returning after seconds does not teleport every pulse
      // the length of its arc.
      const dt = Math.min((now - last) / 1000, 0.1)
      last = now

      const moving = this.arcs.some((a) => a.ep.active)
      if (moving) {
        this.advance(dt)
        this.draw()
        this.settled = false
      } else if (!this.settled) {
        // One last frame so the pulses are cleared from the canvas, then stop.
        this.draw()
        this.settled = true
      }
    }
    cancelAnimationFrame(this.raf)
    last = performance.now()
    this.raf = requestAnimationFrame(tick)
  }

  /** Moves every pulse along its arc by one time step.
   *
   *  `speed` is in pixels per second, converted to a fraction of this arc's
   *  own length. Advancing by a fixed fraction instead would make a long arc's
   *  pulse race across the map while a short one crawls. */
  private advance(dt: number) {
    for (const a of this.arcs) {
      if (a.length <= 0) continue
      a.phase = (a.phase + (a.speed * dt) / a.length) % 1
    }
  }

  private onMove = (e: MouseEvent) => {
    if (this.dragging) return
    const rect = this.canvas.getBoundingClientRect()
    this.hover = this.hit(e.clientX - rect.left, e.clientY - rect.top)
    this.canvas.style.cursor = this.hover ? 'pointer'
      : this.k > 1 ? 'grab' : 'default'
  }

  /** Wheel zoom, about the pointer.
   *
   *  exp of the delta rather than a fixed step per event, because trackpads
   *  send a stream of small deltas and mice send few large ones; a fixed step
   *  makes one of the two useless. */
  private onWheel = (e: WheelEvent) => {
    e.preventDefault()
    const rect = this.canvas.getBoundingClientRect()
    this.zoomBy(Math.exp(-e.deltaY * 0.0015), [e.clientX - rect.left, e.clientY - rect.top])
  }

  private onDown = (e: MouseEvent) => {
    // Nothing to pan when the whole world is already in frame.
    if (this.k <= 1) return
    this.dragging = true
    this.moved = 0
    this.dragFrom = [e.clientX, e.clientY]
    this.canvas.style.cursor = 'grabbing'
  }

  private onDrag = (e: MouseEvent) => {
    if (!this.dragging) return
    const dx = e.clientX - this.dragFrom[0]
    const dy = e.clientY - this.dragFrom[1]
    this.moved += Math.abs(dx) + Math.abs(dy)
    this.dragFrom = [e.clientX, e.clientY]
    const t = this.projection.translate() as [number, number]
    this.applyView([t[0] + dx, t[1] + dy], this.k)
  }

  private onUp = () => {
    if (!this.dragging) return
    this.dragging = false
    this.canvas.style.cursor = this.k > 1 ? 'grab' : 'default'
  }

  private onLeave = () => {
    this.hover = null
  }

  private onClick = (e: MouseEvent) => {
    // A pan ends in a click event. Without this, letting go after dragging the
    // map also opened whatever happened to be under the pointer.
    if (this.moved > 4) { this.moved = 0; return }
    const rect = this.canvas.getBoundingClientRect()
    const hit = this.hit(e.clientX - rect.left, e.clientY - rect.top)
    this.onSelect(hit ? hit.ep.key : null)
  }

  /** Nearest destination dot within a forgiving radius. */
  private hit(x: number, y: number): Arc | null {
    let best: Arc | null = null
    let bestDist = 13 * 13
    for (const a of this.arcs) {
      const p = a.dot
      if (!p) continue
      const dx = p[0] - x
      const dy = p[1] - y
      const d = dx * dx + dy * dy
      if (d < bestDist) {
        bestDist = d
        best = a
      }
    }
    return best
  }

  /** Returns the cached basemap, drawing it first if the cache is cold. */
  private baseLayer(): HTMLCanvasElement | null {
    const { width: w, height: h, dpr } = this
    if (!w || !h) return null
    if (this.basemap && this.basemap.width === Math.round(w * dpr)) return this.basemap

    const c = document.createElement('canvas')
    c.width = Math.round(w * dpr)
    c.height = Math.round(h * dpr)
    const g = c.getContext('2d')
    if (!g) return null
    g.setTransform(dpr, 0, 0, dpr, 0, 0)

    g.fillStyle = this.col.ocean
    g.fillRect(0, 0, w, h)
    g.beginPath()
    // geoPath writes to whichever context it was built with, so it is pointed
    // at the offscreen one for the duration and put back afterwards.
    this.path.context(g)
    this.path(land)
    this.path.context(this.ctx)
    g.fillStyle = this.col.land
    g.fill()
    g.lineWidth = 0.6
    g.strokeStyle = this.col.landEdge
    g.stroke()

    // Borders belong on the basemap rather than the live layer: they never
    // change between frames, so they are drawn once per projection and then
    // copied along with everything else that is static.
    if (this.showCountries && this.borders) {
      this.path.context(g)
      g.beginPath()
      this.path(this.borders.mesh as never)
      this.path.context(this.ctx)
      g.lineWidth = 0.5
      g.strokeStyle = this.col.landEdge
      g.stroke()
      this.drawCountryNames(g as unknown as CanvasRenderingContext2D)
    }

    // Everything that will look identical on the next frame goes in here too.
    // An arc is static unless it is the selected one or it carries a pulse.
    const live = this.ctx
    this.ctx = g as unknown as CanvasRenderingContext2D
    for (const a of this.arcs) {
      if (a.ep.active || a.ep.key === this.selectedIP) continue
      this.drawArc(a, false)
      const p = a.dot
      if (!p) continue
      g.beginPath()
      g.arc(p[0], p[1], 1.9, 0, Math.PI * 2)
      g.fillStyle = a.colour
      g.fill()
    }
    this.ctx = live

    this.basemap = c
    return c
  }

  private draw() {
    const { ctx, width: w, height: h } = this
    if (!w || !h) return

    ctx.clearRect(0, 0, w, h)
    const base = this.baseLayer()
    if (base) {
      ctx.drawImage(base, 0, 0, w, h)
    } else {
      ctx.fillStyle = this.col.ocean
      ctx.fillRect(0, 0, w, h)
    }

    if (!this.origin) return

    const originPt = this.origin.known
      ? this.projection([this.origin.lon, this.origin.lat])
      : this.projection([0, 20])

    // Only the arcs that move. The rest are already in the layer above, which
    // is the entire point: on a busy network they are the overwhelming
    // majority, and they look the same on every frame.
    for (const a of this.arcs) {
      if (!a.ep.active && a.ep.key !== this.selectedIP) continue
      this.drawArc(a, a.ep.key === this.selectedIP)
    }

    // Destination dots, for the same subset; the idle ones are cached.
    for (const a of this.arcs) {
      if (!a.ep.active && a.ep.key !== this.selectedIP) continue
      const p = a.dot
      if (!p) continue
      const sel = a.ep.key === this.selectedIP
      const r = sel ? 4 : a.ep.active ? 2.6 : 1.9
      ctx.beginPath()
      ctx.arc(p[0], p[1], r, 0, Math.PI * 2)
      ctx.fillStyle = sel ? this.col.origin : a.colour
      ctx.fill()
      if (sel) {
        ctx.beginPath()
        ctx.arc(p[0], p[1], 8, 0, Math.PI * 2)
        ctx.strokeStyle = this.col.origin
        ctx.lineWidth = 1
        ctx.globalAlpha = 0.5
        ctx.stroke()
        ctx.globalAlpha = 1
      }
    }

    // Origin marker last, so it is never obscured.
    if (originPt) {
      const pulse = 5 + Math.sin(Date.now() / 420) * 1.6
      ctx.beginPath()
      ctx.arc(originPt[0], originPt[1], pulse, 0, Math.PI * 2)
      ctx.strokeStyle = this.col.origin
      ctx.globalAlpha = 0.45
      ctx.lineWidth = 1.2
      ctx.stroke()
      ctx.globalAlpha = 1
      ctx.beginPath()
      ctx.arc(originPt[0], originPt[1], 3, 0, Math.PI * 2)
      ctx.fillStyle = this.col.origin
      ctx.fill()
    }

    if (this.hover) this.drawTooltip(this.hover)
  }

  /**
   * How solid an arc is drawn, which cannot be one number.
   *
   * A closed arc was drawn at 0.2 whatever else was on screen. On a busy
   * network that is right: six hundred arcs at any more than that stop being
   * lines and become one grey smear over the map. On a quiet one it is close to
   * not drawing them at all, and it measured 1.24:1 against the ocean, which a
   * tester reported as a map whose lines could not be seen. Both complaints are
   * correct about their own map, so the value follows the crowd rather than
   * picking a side: solid when there is room, faint when there is not.
   */
  /**
   * Turns country borders and names on or off.
   *
   * The geometry loads on first use. Failure is silent and leaves the map as it
   * was: a border layer is a nicety, and a dashboard that refuses to draw a map
   * because a decoration would not download is worse than one without borders.
   */
  async setCountries(on: boolean): Promise<void> {
    this.showCountries = on
    if (on && !this.borders) {
      try {
        const topo = (await import('world-atlas/countries-110m.json')).default as never
        const objects = (topo as unknown as { objects: { countries: never } }).objects
        const shapes = feature(topo, objects.countries) as unknown as {
          features: Array<{ properties: { name?: string } }>
        }
        // The interior mesh only: a === b would give every coastline too, which
        // the land layer already draws and which would double the ink.
        const borderMesh = mesh(topo, objects.countries, (a: unknown, b: unknown) => a !== b)
        // **Geographic centroids, not projected ones.** Projecting here would
        // bake in whatever zoom happened to be active when the layer loaded,
        // and every name would then sit where it belonged one zoom level ago.
        const labels: Array<{ name: string; at: [number, number] }> = []
        for (const f of shapes.features) {
          const name = f.properties?.name
          if (!name) continue
          const at = geoCentroid(f as never)
          if (!Number.isFinite(at[0]) || !Number.isFinite(at[1])) continue
          labels.push({ name, at: at as [number, number] })
        }
        this.borders = { mesh: borderMesh, labels }
      } catch {
        this.showCountries = false
      }
    }
    this.basemap = null // borders live on the cached layer
    this.settled = false
    this.draw()
  }

  /**
   * Country names, as many as fit and no more.
   *
   * Placed at each country's centroid and skipped when the space is taken, so a
   * world view names the large countries and zooming in reveals the rest. The
   * alternative, a fixed list by size, is wrong at every zoom except the one it
   * was tuned for.
   */
  private drawCountryNames(g: CanvasRenderingContext2D) {
    if (!this.borders) return
    const placed: Array<{ x0: number; y0: number; x1: number; y1: number }> = []
    g.save()
    g.font = '10px system-ui, -apple-system, sans-serif'
    g.textAlign = 'center'
    g.textBaseline = 'middle'
    g.fillStyle = this.col.textDim
    g.globalAlpha = 0.75
    for (const l of this.borders.labels) {
      const p = this.projection(l.at) as [number, number] | null
      if (!p) continue
      const [x, y] = p
      if (x < 0 || y < 0 || x > this.width || y > this.height) continue
      const w = g.measureText(l.name).width
      const box = { x0: x - w / 2 - 3, y0: y - 7, x1: x + w / 2 + 3, y1: y + 7 }
      if (placed.some((p) => box.x0 < p.x1 && box.x1 > p.x0 && box.y0 < p.y1 && box.y1 > p.y0)) continue
      g.fillText(l.name, x, y)
      placed.push(box)
    }
    g.restore()
  }

  private arcAlpha(active: boolean | undefined): number {
    const crowd = Math.min(1, Math.max(0, (this.arcs.length - 40) / 360))
    const clear = active ? 0.78 : 0.58
    const dense = active ? 0.45 : 0.22
    return clear + (dense - clear) * crowd
  }

  private drawArc(a: Arc, selected: boolean) {
    const { ctx } = this
    if (a.segments.length === 0) return

    ctx.lineWidth = selected ? a.weight + 1 : a.weight
    ctx.strokeStyle = selected ? this.col.origin : a.colour
    ctx.globalAlpha = selected ? 0.9 : this.arcAlpha(a.ep.active)
    for (const seg of a.segments) {
      ctx.beginPath()
      ctx.moveTo(seg[0][0], seg[0][1])
      for (let i = 1; i < seg.length; i++) ctx.lineTo(seg[i][0], seg[i][1])
      ctx.stroke()
    }
    ctx.globalAlpha = 1

    // The travelling pulse: this is what makes the map read as live traffic
    // rather than a static diagram.
    if (a.ep.active && a.flat.length > 1) {
      // Find where along the arc's *drawn length* the pulse currently sits,
      // then interpolate within that segment. Both steps matter: the search
      // keeps the speed constant, the interpolation keeps the motion smooth
      // between samples.
      const target = a.phase * a.length
      let i = 0
      while (i < a.cum.length - 2 && a.cum[i + 1] < target) i++
      const span = a.cum[i + 1] - a.cum[i]
      const frac = span > 0 ? (target - a.cum[i]) / span : 0
      const p0 = a.flat[i]
      const p1 = a.flat[i + 1]
      const p: [number, number] = [
        p0[0] + (p1[0] - p0[0]) * frac,
        p0[1] + (p1[1] - p0[1]) * frac,
      ]
      // A pulse must not be drawn across an antimeridian wrap, where adjacent
      // samples sit on opposite edges of the map.
      if (Math.abs(p1[0] - p0[0]) < this.width * 0.5) {
        ctx.beginPath()
        ctx.arc(p[0], p[1], selected ? 2.6 : 1.8, 0, Math.PI * 2)
        ctx.fillStyle = selected ? this.col.origin : a.colour
        ctx.globalAlpha = 0.95
        ctx.fill()
        ctx.globalAlpha = 1
      }
    }
  }

  private drawTooltip(a: Arc) {
    const { ctx } = this
    const p = a.dot
    if (!p) return

    const title = a.ep.title
    const lines = [a.ep.place, a.ep.who].filter(Boolean) as string[]

    ctx.font = '600 12px -apple-system, system-ui, sans-serif'
    let wide = ctx.measureText(title).width
    ctx.font = '11px ui-monospace, monospace'
    for (const l of lines) wide = Math.max(wide, ctx.measureText(l).width)

    const padX = 9
    const boxW = wide + padX * 2
    const boxH = 20 + lines.length * 14
    let x = p[0] + 12
    let y = p[1] - boxH - 10
    if (x + boxW > this.width - 6) x = p[0] - boxW - 12
    if (y < 6) y = p[1] + 14

    ctx.fillStyle = this.col.tooltipBg
    ctx.strokeStyle = this.col.tooltipEdge
    ctx.lineWidth = 1
    ctx.beginPath()
    ctx.roundRect(x, y, boxW, boxH, 5)
    ctx.fill()
    ctx.stroke()

    ctx.fillStyle = this.col.text
    ctx.font = '600 12px -apple-system, system-ui, sans-serif'
    ctx.fillText(title, x + padX, y + 15)
    ctx.fillStyle = this.col.textDim
    ctx.font = '11px ui-monospace, monospace'
    lines.forEach((l, i) => ctx.fillText(l, x + padX, y + 30 + i * 14))
  }
}
