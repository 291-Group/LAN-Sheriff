// Every message code the backend can emit must resolve in every catalogue.
//
// The server cannot know what language the viewer reads, so anything meant for
// a person travels as a stable code with English prose beside it, and the
// dashboard renders the translation. message() falls back to that prose when it
// does not recognize a code.
//
// That fallback is what makes this worth checking. A code added in Go and not
// added to the catalogues does not crash, does not fail to type-check, and does
// not look broken in development, because the developer reads English and the
// fallback is English. It is wrong only for the eleven audiences least able to
// report it. Nothing else in the build can see this: the codes are Go string
// constants on one side and object keys on the other, so TypeScript checks that
// the catalogues agree with each other and never that they agree with the
// server.
//
// Checks both directions. A code with no translation is the bug above; a
// translation with no code is a string nothing can ever display, which is
// usually the trailing edge of a rename and worth deleting rather than
// translating into twelve languages forever.

import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const hints = join(root, 'internal/types/hints.go')
const i18n = join(root, 'web/src/i18n')

// The constants are grouped and commented, so the value is what matters rather
// than the name: any Hint*, Note* or Err* declared at the top level of a const
// block in this file is a code the dashboard may be handed.
const go = readFileSync(hints, 'utf8')
const codes = [...go.matchAll(/^\t(?:Hint|Note|Err)\w+\s*=\s*"([^"]+)"/gm)].map((m) => m[1])

if (codes.length === 0) {
  console.error('check-msg-codes: no codes found in internal/types/hints.go')
  console.error('  the file moved or the declaration style changed, so this check is now blind')
  process.exit(1)
}

let bad = 0
for (const file of readdirSync(i18n).filter((f) => f.endsWith('.ts') && f !== 'index.ts').sort()) {
  const lang = file.slice(0, -3)
  const src = readFileSync(join(i18n, file), 'utf8')

  const block = src.match(/\n {2}msg:\s*\{(.*?)\n {2}\}/s)
  if (!block) {
    console.error(`check-msg-codes: ${lang} has no msg block`)
    bad++
    continue
  }

  // Keys only: a value may itself contain a colon, so anchor to the start of a
  // line inside the block.
  const keys = new Set([...block[1].matchAll(/^\s{4}([a-z_]+)\s*:/gm)].map((m) => m[1]))

  const missing = codes.filter((c) => !keys.has(c))
  const extra = [...keys].filter((k) => !codes.includes(k))

  if (missing.length) {
    console.error(`check-msg-codes: ${lang} cannot render ${missing.join(', ')}`)
    console.error(`  these fall back to English prose, which is invisible in development`)
    bad++
  }
  if (extra.length) {
    console.error(`check-msg-codes: ${lang} translates ${extra.join(', ')}, which the backend never sends`)
    bad++
  }
}

if (bad) process.exit(1)
console.log(`message codes: all ${codes.length} resolve in all 12 catalogues`)
