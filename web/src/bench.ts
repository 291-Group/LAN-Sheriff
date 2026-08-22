// A benchmark of the Watchtower's real draw path.
//
// Not shipped: this file and bench.html exist so the map's cost can be measured
// rather than argued about. It calls the same class the dashboard uses, with the
// same data shape, and times the private draw() directly instead of going
// through requestAnimationFrame, which does not run at all in a background tab
// and returned zero frames when I first tried to measure this.
import { Watchtower } from './map'
import type { Origin } from './api'

const out = document.getElementById('out') as HTMLDivElement
const log = (s: string) => { out.textContent += s + '\n' }

const origin: Origin = { known: true, lat: 45.5, lon: -73.6, label: 'bench' } as Origin

/** N plausible destinations spread over the globe, a share of them active. */
function endpoints(n: number, activeFraction: number) {
  const eps: unknown[] = []
  for (let i = 0; i < n; i++) {
    const lat = -55 + ((i * 37) % 110)
    const lon = -180 + ((i * 71) % 360)
    eps.push({
      key: `10.0.${(i / 254) | 0}.${i % 254}`,
      lat, lon,
      is_internal: false,
      active: i < n * activeFraction,
      conns: 1 + (i % 40),
      org: `Org ${i}`,    } as never)
  }
  return eps
}

function bench(n: number, activeFraction: number) {
  const canvas = document.getElementById('c') as HTMLCanvasElement
  const tower = new Watchtower(canvas)
  tower.resize(900, 600)
  tower.setData(origin, endpoints(n, activeFraction) as never)

  const draw = () => (tower as unknown as { draw(): void }).draw()

  for (let i = 0; i < 20; i++) draw()          // warm up, and prime the cache
  const N = 120
  const t0 = performance.now()
  for (let i = 0; i < N; i++) draw()
  const per = (performance.now() - t0) / N

  tower.destroy()
  const pct = (per * 60 / 1000) * 100
  log(`  ${String(n).padStart(4)} endpoints, ${String(Math.round(activeFraction*100)).padStart(3)}% active` +
      `  ->  ${per.toFixed(3)} ms/frame   ${pct.toFixed(1)}% of one core at 60fps`)
  return per
}

log('Watchtower draw() cost, measured on the real class\n')
log(`  canvas 900x600, devicePixelRatio ${window.devicePixelRatio}\n`)
for (const n of [12, 100, 300, 500]) bench(n, 0.1)
log('')
for (const f of [0, 0.25, 0.5, 1]) bench(500, f)
log('\ndone')
;(window as unknown as { benchDone: boolean }).benchDone = true
