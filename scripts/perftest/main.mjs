#!/usr/bin/env node
// Measures what the dashboard actually costs, per view, in CPU seconds.
//
// This exists because the previous method was asking a person to watch a laptop
// fan and read a percentage out of Task Manager. That is an anecdote. It cannot
// be repeated, it cannot be compared against last week, it cannot tell a code
// change from a warm room, and it made the owner of the laptop into the
// instrument. Two conclusions were drawn from it that later measurement
// contradicted.
//
// Chrome's DevTools Protocol reports cumulative renderer CPU time through
// Performance.getMetrics. Sampling it either side of a fixed wall-clock window
// gives CPU seconds consumed in that window, and dividing by the window gives
// the fraction of one core the page is using. That is a number. It is the same
// number on any machine, it can be checked into a budget, and it needs nobody
// watching anything.
//
// Driven over a raw WebSocket against the system Chrome: no puppeteer, no
// browser download, nothing added to package.json.
//
//   node scripts/perftest/main.mjs --url http://127.0.0.1:2999 [--seconds 20]

import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, arr) => {
    if (a.startsWith('--')) acc.push([a.slice(2), arr[i + 1]])
    return acc
  }, []),
)
const BASE = args.url || 'http://127.0.0.1:2999'
const WINDOW = Number(args.seconds || 20) * 1000
const PORT = 9333

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

// The views to measure, and why each is here.
const VIEWS = [
  ['#help', 'Help          (no canvas, no polling widgets: the floor)'],
  ['', 'Watchtower    (the animated map)'],
  ['#roster', 'Roster        (a table, plus the freshness ring)'],
  ['#chatter', 'Radio Chatter (a long list, polled)'],
  ['#precinct', 'Precinct Map  (a force graph, animated)'],
  ['#wanted', 'Wanted List   (short list, freshness ring)'],
]

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function cdpTargets() {
  const r = await fetch(`http://127.0.0.1:${PORT}/json/list`)
  return r.json()
}

/** One CDP connection, with promise-per-command. */
function connect(wsUrl) {
  const ws = new WebSocket(wsUrl)
  const pending = new Map()
  let id = 0
  const ready = new Promise((res, rej) => {
    ws.onopen = () => res()
    ws.onerror = (e) => rej(e)
  })
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data)
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg.result)
      pending.delete(msg.id)
    }
  }
  return {
    ready,
    send(method, params = {}) {
      return new Promise((res) => {
        const n = ++id
        pending.set(n, res)
        ws.send(JSON.stringify({ id: n, method, params }))
      })
    },
    close: () => ws.close(),
  }
}

/** TaskDuration is the renderer's total task time: the CPU number we want. */
function metric(metrics, name) {
  return metrics.find((m) => m.name === name)?.value ?? 0
}

async function main() {
  const profile = mkdtempSync(join(tmpdir(), 'ls-perf-'))
  const chrome = spawn(CHROME, [
    // Plain --headless: the "=new" spelling was removed once new headless
    // became the only headless, and passing it makes Chrome 150 start without
    // a debugging port and without saying why.
    '--headless',
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--window-size=1440,900',
    // Deterministic: without this the sample depends on whatever the host GPU
    // is doing, and the point is a number that means the same thing twice.
    '--disable-gpu',
    '--hide-scrollbars',
    'about:blank',
  ], { stdio: 'ignore' })

  const stop = () => {
    chrome.kill()
    try { rmSync(profile, { recursive: true, force: true }) } catch {}
  }
  process.on('exit', stop)

  // Wait for the debugging endpoint.
  let targets = null
  for (let i = 0; i < 60; i++) {
    try { targets = await cdpTargets(); break } catch { await sleep(250) }
  }
  if (!targets) throw new Error('Chrome did not expose a debugging port')

  let page = null
  for (let i = 0; i < 40 && !page; i++) {
    page = (await cdpTargets()).find((t) => t.type === 'page')
    if (!page) await sleep(250)
  }
  if (!page) throw new Error('Chrome exposed a port but never created a page target')
  const cdp = connect(page.webSocketDebuggerUrl)
  await cdp.ready
  await cdp.send('Page.enable')
  await cdp.send('Runtime.enable')
  await cdp.send('Performance.enable')

  console.log(`\n  dashboard : ${BASE}`)
  console.log(`  window    : ${WINDOW / 1000}s per view, headless Chrome, GPU off`)

  // What the dashboard is actually showing, so the numbers can be read in
  // context rather than compared across different amounts of data.
  try {
    const s = await (await fetch(`${BASE}/api/summary`)).json()
    console.log(`  data      : ${s.devices} devices, ${s.endpoints} endpoints, ${s.countries} countries`)
  } catch { console.log('  data      : (could not read /api/summary)') }

  console.log(`\n  view                                              CPU     of one core   long tasks`)
  const results = []
  for (const [hash, label] of VIEWS) {
    await cdp.send('Page.navigate', { url: BASE + '/' + hash })
    // Let the view mount, fetch and settle before the clock starts, so this
    // measures steady state rather than page load.
    await sleep(6000)

    const before = (await cdp.send('Performance.getMetrics')).metrics
    const t0 = Date.now()
    await sleep(WINDOW)
    const after = (await cdp.send('Performance.getMetrics')).metrics
    const elapsed = (Date.now() - t0) / 1000

    const cpu = metric(after, 'TaskDuration') - metric(before, 'TaskDuration')
    const script = metric(after, 'ScriptDuration') - metric(before, 'ScriptDuration')
    const layout = metric(after, 'LayoutDuration') - metric(before, 'LayoutDuration')
    const recalc = metric(after, 'RecalcStyleDuration') - metric(before, 'RecalcStyleDuration')
    const frac = cpu / elapsed

    results.push({ label, cpu, frac, script, layout, recalc })
    console.log(
      `  ${label.padEnd(48)}${cpu.toFixed(2)}s   ${(frac * 100).toFixed(1).padStart(6)}%` +
      `      script ${script.toFixed(2)}s`,
    )
  }

  const floor = results.find((r) => r.label.startsWith('Help'))
  console.log('\n  Read against the Help figure, which is the floor: every view pays')
  console.log('  the polling and the WebSocket, and only the difference is the view.')
  for (const r of results) {
    if (r === floor) continue
    const over = (r.frac - floor.frac) * 100
    console.log(`    ${r.label.split('(')[0].trim().padEnd(14)} costs ${over >= 0 ? '+' : ''}${over.toFixed(1)}% of a core over Help`)
  }
  // A real CPU profile of the most expensive view, because knowing that a view
  // costs 45% of a core is only half an answer. The first attempt at this
  // problem timed one function in isolation, concluded the cost was 0.4% of a
  // core, and was wrong by two orders of magnitude precisely because it guessed
  // which function mattered instead of asking.
  const worst = results.reduce((a, b) => (b.frac > a.frac ? b : a))
  console.log(`\n  CPU profile of the most expensive view: ${worst.label.split('(')[0].trim()}`)
  await cdp.send('Page.navigate', { url: BASE + '/' + (VIEWS.find(v => worst.label.startsWith(v[1].split('(')[0].trim()))?.[0] ?? '') })
  await sleep(6000)
  await cdp.send('Profiler.enable')
  await cdp.send('Profiler.setSamplingInterval', { interval: 200 })
  await cdp.send('Profiler.start')
  await sleep(10000)
  const { profile: cpuProfile } = await cdp.send('Profiler.stop')

  // Self time per function, from the sample counts.
  const byId = new Map(cpuProfile.nodes.map((n) => [n.id, n]))
  const self = new Map()
  const total = cpuProfile.samples.length
  for (const id of cpuProfile.samples) {
    const n = byId.get(id)
    if (!n) continue
    const f = n.callFrame
    const key = `${f.functionName || '(anonymous)'}  ${f.url.split('/').pop()}:${f.lineNumber + 1}`
    self.set(key, (self.get(key) || 0) + 1)
  }
  const top = [...self.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12)
  console.log(`  ${total} samples over 10s\n`)
  for (const [name, count] of top) {
    const pct = (count / total) * 100
    if (pct < 1) continue
    console.log(`    ${pct.toFixed(1).padStart(5)}%  ${name}`)
  }

  console.log()
  cdp.close()
  stop()
}

main().catch((e) => { console.error(e); process.exit(1) })
