#!/usr/bin/env node
// Ablation: measure the Watchtower with pieces of it switched off, so the cost
// is attributed to a part rather than assigned to one by argument.
//
// Needed because every attribution so far has been wrong. The map was blamed
// for a cost that turned out to be 85% basemap; the basemap fix was credited
// with an improvement the numbers did not support; and an idle-skip that should
// have made the canvas free on a map with zero active endpoints changed nothing
// measurable. At that point the honest move is to stop reasoning about which
// part is expensive and start removing parts.
//
// Each variant runs in its own fresh page load, and each is measured several
// times, because a single sample on this harness varies by about five points
// and a comparison inside that range means nothing.
//
//   node scripts/perftest/ablate.mjs --url http://127.0.0.1:2999

import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const args = Object.fromEntries(
  process.argv.slice(2).reduce((a, v, i, arr) => (v.startsWith('--') && a.push([v.slice(2), arr[i + 1]]), a), []),
)
const BASE = args.url || 'http://127.0.0.1:2999'
const WINDOW = Number(args.seconds || 12) * 1000
const REPEATS = Number(args.repeats || 3)
const PORT = 9335
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Each variant is a snippet run after load. Between them they take the view
// apart: canvas, then the destinations list, then the timeline.
const VARIANTS = [
  ['whole view', ''],
  ['canvas hidden (removes paint, keeps its JS)', `document.querySelectorAll('canvas').forEach(c => c.style.display='none')`],
  ['canvas removed (removes paint and its JS)', `document.querySelectorAll('canvas').forEach(c => c.remove())`],
  ['destinations panel hidden', `document.querySelectorAll('aside,.side,.destinations,[class*=dest]').forEach(e => e.style.display='none')`],
  ['timeline hidden', `document.querySelectorAll('[class*=timeline],[class*=histogram]').forEach(e => e.style.display='none')`],
]

function connect(wsUrl) {
  const ws = new WebSocket(wsUrl)
  const pending = new Map()
  let id = 0
  const ready = new Promise((res, rej) => { ws.onopen = () => res(); ws.onerror = rej })
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data)
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg.result); pending.delete(msg.id) }
  }
  return {
    ready,
    send: (method, params = {}) => new Promise((res) => { const n = ++id; pending.set(n, res); ws.send(JSON.stringify({ id: n, method, params })) }),
    close: () => ws.close(),
  }
}
const metric = (m, n) => m.find((x) => x.name === n)?.value ?? 0
const median = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)]

async function main() {
  const profile = mkdtempSync(join(tmpdir(), 'ls-ablate-'))
  const chrome = spawn(CHROME, ['--headless', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
    '--no-first-run', '--window-size=1440,900', '--disable-gpu', '--hide-scrollbars', 'about:blank'], { stdio: 'ignore' })
  const stop = () => { chrome.kill(); try { rmSync(profile, { recursive: true, force: true }) } catch {} }
  process.on('exit', stop)

  let page = null
  for (let i = 0; i < 80 && !page; i++) {
    try { page = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === 'page') } catch {}
    if (!page) await sleep(250)
  }
  if (!page) throw new Error('no page target')
  const cdp = connect(page.webSocketDebuggerUrl)
  await cdp.ready
  await cdp.send('Page.enable'); await cdp.send('Runtime.enable'); await cdp.send('Performance.enable')

  console.log(`\n  Watchtower ablation, ${REPEATS} runs of ${WINDOW / 1000}s each, median reported`)
  console.log(`  ${BASE}\n`)
  console.log('  variant                                        median   spread')

  const out = []
  for (const [label, js] of VARIANTS) {
    const samples = []
    for (let r = 0; r < REPEATS; r++) {
      await cdp.send('Page.navigate', { url: BASE + '/' })
      await sleep(6000)
      if (js) await cdp.send('Runtime.evaluate', { expression: js })
      await sleep(1500)
      const before = (await cdp.send('Performance.getMetrics')).metrics
      const t0 = Date.now()
      await sleep(WINDOW)
      const after = (await cdp.send('Performance.getMetrics')).metrics
      const frac = (metric(after, 'TaskDuration') - metric(before, 'TaskDuration')) / ((Date.now() - t0) / 1000)
      samples.push(frac * 100)
    }
    const med = median(samples)
    out.push([label, med])
    console.log(`  ${label.padEnd(46)}${med.toFixed(1).padStart(6)}%   ${Math.min(...samples).toFixed(1)} to ${Math.max(...samples).toFixed(1)}`)
  }

  const whole = out[0][1]
  console.log('\n  attributable cost, against the whole view:')
  for (const [label, med] of out.slice(1)) {
    const saved = whole - med
    console.log(`    ${label.padEnd(46)}${saved >= 0 ? '-' : '+'}${Math.abs(saved).toFixed(1)} points`)
  }
  console.log('\n  A variant that saves nothing means that part was not the cost,')
  console.log('  whatever anybody assumed.\n')
  cdp.close(); stop()
}
main().catch((e) => { console.error(e); process.exit(1) })
