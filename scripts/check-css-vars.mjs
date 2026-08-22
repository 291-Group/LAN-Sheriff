#!/usr/bin/env node
// Fails if a CSS custom property is used but never defined.
//
// This exists because it happened. A batch of new rules referenced --gap, --line,
// --muted and --panel, none of which were ever declared. CSS does not warn about
// this: an undefined variable with no fallback makes the whole declaration
// invalid, so `gap: var(--gap)` silently became no gap at all. The result was a
// view with no spacing between its panes, and nothing anywhere reported a problem.
//
// The variables with colour fallbacks were worse, because they looked fine while
// quietly ignoring the theme.

import { readFileSync, readdirSync } from 'node:fs'

// Walked rather than globbed. `fs.globSync` arrived in Node 22, and this project
// promises Node 20+, so the check passed on the author's Node 25 and failed on
// CI's Node 20, which is the whole reason a version floor is worth honouring in
// the tooling that enforces the other rules.
function cssFiles(dir, base = '') {
  const out = []
  for (const entry of readdirSync(new URL(dir, import.meta.url), { withFileTypes: true })) {
    const rel = base ? `${base}/${entry.name}` : entry.name
    if (entry.isDirectory()) out.push(...cssFiles(`${dir}${entry.name}/`, rel))
    else if (entry.name.endsWith('.css')) out.push(rel)
  }
  return out
}

const files = cssFiles('../web/src/').map((f) => `src/${f}`)
let failed = false

for (const rel of files) {
  const path = new URL(`../web/${rel}`, import.meta.url)
  const css = readFileSync(path, 'utf8')

  const defined = new Set([...css.matchAll(/(--[a-z0-9-]+)\s*:/g)].map((m) => m[1]))
  const used = new Map()
  for (const m of css.matchAll(/var\(\s*(--[a-z0-9-]+)\s*([,)])/g)) {
    // A declared fallback means the author accepted the variable may be absent.
    if (m[2] === ',') continue
    used.set(m[1], (used.get(m[1]) ?? 0) + 1)
  }

  const missing = [...used.keys()].filter((v) => !defined.has(v)).sort()
  if (missing.length > 0) {
    failed = true
    console.error(`${rel}: used but never defined, and with no fallback:`)
    for (const v of missing) console.error(`  ${v}  (${used.get(v)} uses)`)
  }
}

if (failed) {
  console.error('\nAn undefined variable makes the whole declaration invalid, so this silently removes styling.')
  process.exit(1)
}
console.log('css variables: all resolved')
