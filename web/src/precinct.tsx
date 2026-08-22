import { useCallback, useEffect, useRef, useState } from 'preact/hooks'
import {
  forceSimulation, forceLink, forceManyBody, forceCollide, forceRadial, forceCenter,
  type Simulation, type SimulationNodeDatum, type SimulationLinkDatum,
} from 'd3-force'
import { fetchTopology, fmtBytes, flag, type Filter, type Topology, type TopoNode } from './api'
import { useI18n, fill } from './i18n'
import { Freshness, usePolling } from './freshness'

/**
 * The Precinct Map: this network as a diagram rather than a list.
 *
 * The layout is radial and that is the whole design. Devices on this network sit
 * in the middle; the organizations they talk to are pushed to an outer ring. A
 * plain force graph would let the two mix, and the single most useful thing this
 * view can say (which of these things are *mine*) would be lost in the
 * arrangement.
 *
 * Drawn on canvas rather than SVG for the same reason the Watchtower is: a few
 * hundred nodes redrawn sixty times a second is thousands of DOM mutations per
 * frame in SVG, and none of it needs to be an element.
 */

const REFRESH_MS = 15000

type Node = TopoNode & SimulationNodeDatum & { r: number }
type Link = SimulationLinkDatum<Node> & { conns: number }

export function Precinct({ filter, layer = '' }: { filter: Filter; layer?: string }) {
  const { t } = useI18n()
  const [topo, setTopo] = useState<Topology | null>(null)
  // Hover lives in a ref, not state. It changes on every pointer move, and as an
  // effect dependency it tore down and rebuilt the render loop dozens of times a
  // second. The canvas reads it directly; only the tooltip needs a re-render, and
  // that is throttled to actual changes of node.
  const hoverRef = useRef<Node | null>(null)
  const [hoverId, setHoverId] = useState<string | null>(null)

  const load = useCallback(async () => {
    setTopo(await fetchTopology(filter, layer))
  }, [filter, layer])

  const { updatedAt, busy, refresh } = usePolling(load, REFRESH_MS)

  // **Changing the layer has to redraw now, not at the next poll.**
  //
  // usePolling runs its callback once on mount and then on a timer, so a new
  // `load` closure carrying a different layer sat unused until the next tick.
  // Selecting a peer appeared to do nothing at all for as long as the interval,
  // which is exactly the "it does not work" this whole change is fixing.
  //
  // Skipped on the first render, where usePolling has already fetched.
  const first = useRef(true)
  useEffect(() => {
    if (first.current) { first.current = false; return }
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layer])

  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const stateRef = useRef<{
    nodes: Node[]
    links: Link[]
    sim: Simulation<Node, Link> | null
    lastDims?: { w: number; h: number }
  }>({ nodes: [], links: [], sim: null })
  const sizeRef = useRef({ w: 0, h: 0 })
  // Mirrored into state so the layout rebuilds once the size is known. Without
  // this the simulation is created against 0x0: forceCenter lands on the origin
  // and the radial ring has zero radius, so the whole graph piles into the
  // top-left corner and the devices are pushed off the edge.
  const [dims, setDims] = useState({ w: 0, h: 0 })

  // Build or update the simulation when the graph changes.
  useEffect(() => {
    if (!topo || !canvasRef.current) return
    // Nothing to lay out against yet; the resize observer will bring us back.
    if (dims.w === 0 || dims.h === 0) return
    const st = stateRef.current

    // A refresh that changes nothing structural must not disturb the picture.
    //
    // Rebuilding the simulation ran at least one tick, and forceCenter is not
    // scaled by alpha, it shifts every node a fixed fraction of the way toward
    // the centre whenever it runs. With the graph's centroid left of centre,
    // each press of refresh slid the whole diagram to the right.
    //
    // So when the same nodes come back with new counts, their data is updated in
    // place and the layout is left completely alone.
    if (st.sim && !structureChanged(st, topo, dims)) {
      const incoming = new Map(topo.nodes.map((n) => [n.id, n]))
      for (const node of st.nodes) {
        const next = incoming.get(node.id)
        if (!next) continue
        node.conns = next.conns
        node.bytes = next.bytes
        node.label = next.label
        node.type = next.type
        node.online = next.online
        node.trust = next.trust
        node.new = next.new
        node.r = radiusFor(next)
      }
      return
    }

    const width = dims.w, height = dims.h
    // The ring sits well inside the shorter edge so that a node's label, drawn
    // below it, is not clipped by the panel.
    const ring = Math.min(width, height) * 0.36

    // Carry positions across refreshes by id. Rebuilding from scratch every
    // fifteen seconds would fling the whole diagram apart and reassemble it,
    // which makes it impossible to follow anything.
    const previous = new Map(st.nodes.map((n) => [n.id, n]))

    // Seed new nodes where they belong instead of letting the simulation place
    // them at the origin. Unseeded, d3 arranges nodes in a spiral around (0,0)
    // and the forces then drag them across the panel, the diagram visibly flies
    // in from the corner on every first load.
    const nodes: Node[] = topo.nodes.map((n) => {
      const old = previous.get(n.id)
      if (old && old.x != null) {
        return { ...n, r: radiusFor(n), x: old.x, y: old.y, vx: old.vx, vy: old.vy }
      }
      // Seed from a hash of the node's identity, not from its position in the
      // array.
      //
      // The array order is not stable: devices come back sorted by last-seen,
      // which changes constantly, so an index-based seed gave a different
      // starting arrangement on every load and the diagram appeared to scatter
      // differently each time. Hashing the id means the same network always
      // lays out the same way.
      const angle = (hash(n.id) % 3600) / 3600 * Math.PI * 2
      const x = n.kind === 'org'
        ? width / 2 + Math.cos(angle) * ring
        : width / 2 + Math.cos(angle) * 18
      const y = n.kind === 'org'
        ? height / 2 + Math.sin(angle) * ring
        : height / 2 + Math.sin(angle) * 18
      return { ...n, r: radiusFor(n), x, y, vx: 0, vy: 0 }
    })
    const byId = new Map(nodes.map((n) => [n.id, n]))
    const links: Link[] = topo.edges
      .map((e) => ({ source: byId.get(e.source)!, target: byId.get(e.target)!, conns: e.conns }))
      .filter((l) => l.source && l.target)

    st.nodes = nodes
    st.links = links
    st.lastDims = { w: dims.w, h: dims.h }

    st.sim?.stop()
    st.sim = forceSimulation<Node, Link>(nodes)
      .force('link', forceLink<Node, Link>(links).id((d) => d.id).distance(70).strength(0.25))
      .force('charge', forceManyBody<Node>().strength(-160))
      // Collision uses the drawn radius plus label room, so nodes do not overlap
      // into an unreadable clump.
      .force('collide', forceCollide<Node>((d) => d.r + 10))
      .force('center', forceCenter(width / 2, height / 2).strength(0.03))
      // The separation: everything on this network is held near the centre,
      // everything external is pushed out to a ring.
      .force('radial', forceRadial<Node>((d) => (d.kind === 'org' ? ring : 0), width / 2, height / 2)
        .strength((d) => (d.kind === 'org' ? 0.35 : 0.7)))
      // Reheat only when the graph's shape changed.
      //
      // A refresh usually returns the same nodes with new counts, and restarting
      // the simulation for that made the whole diagram twitch every fifteen
      // seconds for no reason a viewer could see. A first layout runs hot; an
      // arrival or departure gets a gentle nudge; identical membership does not
      // disturb the picture at all.
      .alpha(previous.size === 0 ? 0.9 : membershipChanged(previous, nodes) ? 0.12 : 0)
      .restart()

    return () => { st.sim?.stop() }
  }, [topo, dims])

  // One paint loop for the component's lifetime.
  //
  // Size comes from a ResizeObserver rather than from measuring the wrapper every
  // frame: reading a bounding box and then writing canvas.style in the same frame
  // forces a synchronous layout on each pass.
  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if (!canvas || !wrap) return

    const size = { w: 0, h: 0 }
    const resize = () => {
      const r = wrap.getBoundingClientRect()
      const dpr = window.devicePixelRatio || 1
      size.w = Math.max(1, Math.round(r.width))
      size.h = Math.max(1, Math.round(r.height))
      canvas.width = Math.round(size.w * dpr)
      canvas.height = Math.round(size.h * dpr)
      canvas.style.width = `${size.w}px`
      canvas.style.height = `${size.h}px`
      sizeRef.current = { ...size }
      // Only meaningful changes restart the layout; a one-pixel scrollbar
      // adjustment must not reheat the simulation.
      setDims((prev) =>
        Math.abs(prev.w - size.w) > 8 || Math.abs(prev.h - size.h) > 8
          ? { w: size.w, h: size.h }
          : prev)
    }
    resize()

    const ro = new ResizeObserver(resize)
    ro.observe(wrap)

    // The palette is read once per frame, not once per node: every cssVar call
    // is a forced style resolution, and doing it inside the draw loop made the
    // cost scale with the size of the graph.
    let palette = readPalette()
    const themeWatch = new MutationObserver(() => { palette = readPalette() })
    themeWatch.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })

    let raf = 0
    const paint = () => {
      const st = stateRef.current

      draw(canvas, size, palette, st.nodes, st.links, hoverRef.current)
      raf = requestAnimationFrame(paint)
    }
    raf = requestAnimationFrame(paint)

    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      themeWatch.disconnect()
    }
  }, [])

  const onMove = (e: MouseEvent) => {
    const rect = canvasRef.current!.getBoundingClientRect()
    const found = nodeAt(stateRef.current.nodes, e.clientX - rect.left, e.clientY - rect.top)
    hoverRef.current = found
    // Re-render only when the hovered node actually changes, rather than on
    // every pixel of movement.
    setHoverId((prev) => (found?.id ?? null) === prev ? prev : (found?.id ?? null))
  }

  return (
    <div class="precinct">
      <div class="precinct-head panel">
        <span class="precinct-legend">
          <span class="key device" /> {t.precinct.thisNetwork}
          <span class="key org" /> {t.precinct.destinations}
          {/* Only when a peer's devices are actually on screen. A legend entry
              for something absent is noise on every ordinary install. */}
          {topo?.nodes.some((n) => n.kind === 'peer_device') && (
            <><span class="key peer" /> {t.watchtower.legendReported}</>
          )}
        </span>
        {topo && topo.truncated > 0 && (
          <span class="precinct-note">
            {fill(t.precinct.truncated, { count: String(topo.truncated) })}
          </span>
        )}
        <Freshness updatedAt={updatedAt} intervalMs={REFRESH_MS} busy={busy} onRefresh={refresh} />
      </div>

      <div class="precinct-canvas panel" ref={wrapRef}>
        <canvas
          ref={canvasRef}
          onMouseMove={onMove}
          onMouseLeave={() => { hoverRef.current = null; setHoverId(null) }}
        />
        {/* The same shape as the Roster and the Wanted List, rather than one
            bare sentence on a blank canvas. An emptyHint string already existed
            and was never rendered, so the view most likely to be empty on a
            fresh install was also the least explained. */}
        {topo && topo.nodes.length === 0 && (
          <div class="precinct-empty">
            <h2>{t.nav.precinct}</h2>
            <p>{t.precinct.empty}</p>
            <span class="milestone">{t.precinct.emptyHint}</span>
          </div>
        )}
        {hoverId && hoverRef.current && (
          <div
            class="precinct-tip"
            style={{ left: `${hoverRef.current.x ?? 0}px`, top: `${hoverRef.current.y ?? 0}px` }}
          >
            {/* **Everything the node already carries.**

                This showed a label and one line: a connection count for a
                destination, a device type for a device. The node also carries
                country, bytes, online state and whether this network had ever
                contacted that destination before, and none of it was rendered.
                The last of those is the most interesting fact on the map and it
                was being discarded. */}
            <b>{hoverRef.current.label}</b>
            {hoverRef.current.kind === 'org' ? (
              <>
                <span>
                  {hoverRef.current.country ? `${flag(hoverRef.current.country)} ${hoverRef.current.country} \u00b7 ` : ''}
                  {fill(t.precinct.connections, { count: hoverRef.current.conns.toLocaleString() })}
                </span>
                {hoverRef.current.bytes > 0 && (
                  <span>{fmtBytes(hoverRef.current.bytes)}</span>
                )}
                {hoverRef.current.new && (
                  <span class="tip-new">{t.precinct.firstContact}</span>
                )}
              </>
            ) : (
              <>
                <span>
                  {hoverRef.current.type ? (t.deviceType as any)[hoverRef.current.type] ?? '' : ''}
                  {hoverRef.current.online === undefined ? '' :
                    `${hoverRef.current.type ? ' \u00b7 ' : ''}${hoverRef.current.online ? t.roster.online : t.roster.offline}`}
                </span>
                {hoverRef.current.conns > 0 && (
                  <span>
                    {fill(t.precinct.connections, { count: hoverRef.current.conns.toLocaleString() })}
                    {hoverRef.current.bytes > 0 ? ` \u00b7 ${fmtBytes(hoverRef.current.bytes)}` : ''}
                  </span>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

/** radiusFor sizes a node by how much it accounts for, with a floor so the
 *  quietest node is still a target you can point at. */
function radiusFor(n: TopoNode): number {
  if (n.kind === 'gateway') return 13
  if (n.kind === 'device' || n.kind === 'peer_device') return 10
  // Square root, not linear: area is what the eye compares, and a linear radius
  // makes a busy destination swallow the diagram.
  return Math.max(4, Math.min(18, 3 + Math.sqrt(n.conns) * 0.6))
}

function nodeAt(nodes: Node[], x: number, y: number): Node | null {
  // Reverse order so the node drawn on top is the one picked.
  for (let i = nodes.length - 1; i >= 0; i--) {
    const n = nodes[i]
    if (n.x == null || n.y == null) continue
    const dx = n.x - x, dy = n.y - y
    if (dx * dx + dy * dy <= (n.r + 4) * (n.r + 4)) return n
  }
  return null
}

/** Palette is read once per frame and on theme change, never per node. */
type Palette = ReturnType<typeof readPalette>

function readPalette() {
  const cs = getComputedStyle(document.documentElement)
  const v = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback
  return {
    line: v('--arc-idle', '#adb9c9'),
    calm: v('--calm', '#2f7fd4'),
    star: v('--star', '#d9a227'),
    warm: v('--warm', '#e0842c'),
    ok: v('--ok', '#2c9e6b'),
    // The same purple the Watchtower gives a peer's arcs.
    peer: v('--arc-peer', '#8b6fc4'),
    text: v('--text', '#16202e'),
    faint: v('--text-faint', '#8592a6'),
    sans: v('--sans', 'system-ui, sans-serif'),
  }
}

function draw(
  canvas: HTMLCanvasElement,
  size: { w: number; h: number },
  col: Palette,
  nodes: Node[],
  links: Link[],
  hover: Node | null,
) {
  const width = size.w, height = size.h
  const dpr = window.devicePixelRatio || 1

  const ctx = canvas.getContext('2d')
  if (!ctx) return
  ctx.save()
  ctx.scale(dpr, dpr)
  ctx.clearRect(0, 0, width, height)

  // Edges first, so nodes sit on top of them.
  ctx.lineWidth = 1
  for (const l of links) {
    const s = l.source as Node, tg = l.target as Node
    if (s.x == null || tg.x == null) continue
    const touched = hover && (hover.id === s.id || hover.id === tg.id)
    ctx.strokeStyle = touched ? col.calm : col.line
    ctx.globalAlpha = touched ? 0.85 : 0.28
    ctx.beginPath()
    ctx.moveTo(s.x!, s.y!)
    ctx.lineTo(tg.x!, tg.y!)
    ctx.stroke()
  }
  ctx.globalAlpha = 1

  for (const n of nodes) {
    if (n.x == null || n.y == null) continue
    ctx.beginPath()
    ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2)
    ctx.fillStyle = fillFor(n, col)
    ctx.globalAlpha = n.kind === 'device' && n.online === false ? 0.4 : 1
    ctx.fill()

    // A ring marks an organization this network had not contacted before, which
    // is the thing worth noticing on a map you glance at.
    if (n.new) {
      ctx.globalAlpha = 1
      ctx.strokeStyle = col.warm
      ctx.lineWidth = 2
      ctx.beginPath()
      ctx.arc(n.x, n.y, n.r + 3, 0, Math.PI * 2)
      ctx.stroke()
      ctx.lineWidth = 1
    }
    ctx.globalAlpha = 1

  }

  drawLabels(ctx, col, nodes, hover)
  ctx.restore()
}

/**
 * drawLabels writes as many names as will fit without overlapping.
 *
 * The first version skipped any destination below a fixed size, which left dots
 * on the map that could only be identified by pointing at them. But size is the
 * wrong test: what actually matters is whether there is room. So labels are
 * placed largest first and each one is skipped only if it would collide with a
 * label already drawn, a quiet destination in empty space gets named, and a
 * cluster does not turn into overlapping text.
 *
 * Devices and the gateway are always labelled: there are few of them and they
 * are the things a person is looking for.
 */
function drawLabels(ctx: CanvasRenderingContext2D, col: Palette, nodes: Node[], hover: Node | null) {
  type Box = { x0: number; y0: number; x1: number; y1: number }
  const placed: Box[] = []
  const overlaps = (b: Box) =>
    placed.some((p) => b.x0 < p.x1 && b.x1 > p.x0 && b.y0 < p.y1 && b.y1 > p.y0)

  // **The circles count as occupied too.**
  //
  // Collision was checked against labels already drawn and nothing else, so a
  // name never landed on another name but landed on other nodes constantly:
  // "Cisco OpenDNS, LLC" written across a destination, an address printed
  // through the dot above it. On a network of thirty nodes that is most of the
  // map, and a label sitting on a circle is harder to read than no label,
  // because the reader cannot tell which of the two things it belongs to.
  //
  // Seeded before any text is placed, so the rule applies from the first label
  // rather than only to whatever happens to be drawn later. A node's own circle
  // is not in the way of its own name: the text sits below the circle by
  // construction, and excluding it here would make every label collide with
  // itself and vanish.
  const circles = new Map<string, Box>()
  for (const n of nodes) {
    if (n.x == null || n.y == null) continue
    circles.set(n.id, { x0: n.x - n.r, y0: n.y - n.r, x1: n.x + n.r, y1: n.y + n.r })
  }
  const hitsAnotherCircle = (b: Box, ownID: string) => {
    for (const [id, c] of circles) {
      if (id === ownID) continue
      if (b.x0 < c.x1 && b.x1 > c.x0 && b.y0 < c.y1 && b.y1 > c.y0) return true
    }
    return false
  }

  // Largest first, so when two labels compete the more significant one wins.
  // The hovered node is forced to the front so it is never the one dropped.
  const order = [...nodes].sort((a, b) => {
    if (hover) {
      if (a.id === hover.id) return -1
      if (b.id === hover.id) return 1
    }
    const rank = (n: Node) => (n.kind === 'org' ? 0 : 1)
    if (rank(a) !== rank(b)) return rank(b) - rank(a)
    return b.r - a.r
  })

  ctx.textAlign = 'center'
  ctx.textBaseline = 'top'

  for (const n of order) {
    if (n.x == null || n.y == null) continue
    const isDevice = n.kind !== 'org'
    const text = truncate(n.label, isDevice ? 22 : 18)
    ctx.font = `${isDevice ? 11 : 10}px ${col.sans}`

    const w = ctx.measureText(text).width
    const h = isDevice ? 13 : 12

    // **Four places to try, not one.**
    //
    // A label went below its node or nowhere. Adding circles to the collision
    // set then meant that in any tight cluster almost every name was dropped:
    // on a nine-device household, seven devices sat unlabelled in the middle of
    // the map, which is worse than the overlapping text the circle rule was
    // added to prevent. Both problems are the same missing idea, that a name
    // that does not fit underneath may fit somewhere else.
    //
    // Below first, because that is where a reader expects it and where the
    // majority still land. Then above, then the two sides. Only a node with no
    // room on any side goes unlabelled, and by then that is the honest answer.
    const spots = [
      { x: n.x, y: n.y + n.r + 4, align: 'center' as CanvasTextAlign },
      { x: n.x, y: n.y - n.r - h - 3, align: 'center' as CanvasTextAlign },
      { x: n.x + n.r + 5, y: n.y - h / 2 + 1, align: 'left' as CanvasTextAlign },
      { x: n.x - n.r - 5, y: n.y - h / 2 + 1, align: 'right' as CanvasTextAlign },
    ]

    let chosen: { x: number; y: number; align: CanvasTextAlign; box: Box } | null = null
    for (const s of spots) {
      const x0 = s.align === 'center' ? s.x - w / 2 : s.align === 'left' ? s.x : s.x - w
      const box = { x0: x0 - 2, y0: s.y - 1, x1: x0 + w + 2, y1: s.y + h }
      if (n.id === hover?.id || (!overlaps(box) && !hitsAnotherCircle(box, n.id))) {
        chosen = { ...s, box }
        break
      }
    }
    if (!chosen) continue

    ctx.textAlign = chosen.align
    ctx.fillStyle = n.id === hover?.id ? col.text : col.faint
    ctx.fillText(text, chosen.x, chosen.y)
    ctx.textAlign = 'center'
    placed.push(chosen.box)
  }
}

function fillFor(n: Node, col: Palette): string {
  if (n.kind === 'gateway') return col.star
  if (n.kind === 'device') return n.trust === 'watched' ? col.warm : col.ok
  // A peer's device is on somebody else's network, so it is neither one of ours
  // nor a destination. It gets the colour peer arcs already use on the
  // Watchtower, so the two views agree about what purple means.
  //
  // Without this it fell through to the destination colour and the destination
  // size, and another household's television was drawn as though it were a
  // company this network had contacted.
  if (n.kind === 'peer_device') return col.peer
  return col.calm
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + '…'
}

/**
 * structureChanged reports whether anything about the graph requires a new
 * layout: a node arriving or leaving, or the panel being resized.
 *
 * Traffic counts deliberately do not count. They change on every refresh and are
 * read straight from the node data at paint time, so they need no layout work at
 * all.
 */
function structureChanged(
  st: { nodes: Node[]; lastDims?: { w: number; h: number } },
  topo: Topology,
  dims: { w: number; h: number },
): boolean {
  if (st.lastDims?.w !== dims.w || st.lastDims?.h !== dims.h) return true
  if (st.nodes.length !== topo.nodes.length) return true
  const have = new Set(st.nodes.map((n) => n.id))
  return topo.nodes.some((n) => !have.has(n.id))
}

/**
 * membershipChanged reports whether the set of nodes differs, ignoring their
 * traffic counts.
 *
 * Counts change on every refresh and are drawn from the node data directly, so
 * they need no layout work. Only an arrival or a departure changes where things
 * should sit.
 */
function membershipChanged(previous: Map<string, Node>, next: Node[]): boolean {
  if (previous.size !== next.length) return true
  for (const n of next) {
    if (!previous.has(n.id)) return true
  }
  return false
}

/**
 * hash turns a node id into a stable number.
 *
 * FNV-1a, chosen because it is four lines and has no dependencies. The only
 * requirement is that the same id always produces the same value, so that the
 * layout of a given network is reproducible across page loads.
 */
function hash(s: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return Math.abs(h)
}
