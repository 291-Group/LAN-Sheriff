// Every artefact name the README tells somebody to download must be one the
// release actually produces.
//
// # Why this needs a machine
//
// The README said to take `lan-sheriff_darwin_arm64` and `mv` it into place.
// The release has never published that file: assemble.sh packs
// `lan-sheriff_<version>_darwin_arm64.tar.gz` with a binary called
// `lan-sheriff` inside it. The Windows section was worse, naming a bare `.exe`
// against a release that only ever produced archives.
//
// Nothing could catch that. Both halves were correct in isolation, the drift
// was between two files nobody diffs, and it is the first instruction a new
// user follows, so the failure lands on exactly the people with the least
// context to recover from it. A tester hit it at a friend's house.
//
// Checks the shape rather than a fixed list, because the version moves: any
// lan-sheriff_* token in the README must match the pattern assemble.sh builds
// its names from, and every platform the release publishes for must be
// reachable from the README.
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const readme = readFileSync(join(root, 'README.md'), 'utf8')
const assemble = readFileSync(join(root, 'scripts/release/assemble.sh'), 'utf8')

// The one place the names are built: name="${BIN}_${VERSION}_${goos}_${goarch}${suffix}"
if (!/name="\$\{BIN\}_\$\{VERSION\}_\$\{goos\}_\$\{goarch\}\$\{suffix\}"/.test(assemble)) {
  console.error('check-downloads: assemble.sh no longer builds names the way this check assumes.')
  console.error('  update this check, because it is now blind.')
  process.exit(1)
}

// Tokens in the README that look like a downloadable artefact. Deliberately
// ignores the export filenames (lan-sheriff-flows-...csv), which are produced
// by the app rather than the release, and code identifiers with a slash.
const tokens = [...readme.matchAll(/`(lan-sheriff_[A-Za-z0-9_.<>-]+)`/g)].map((m) => m[1])

const bad = []
for (const t of new Set(tokens)) {
  // Accepted: lan-sheriff_<version>_<os>_<arch>[_portable].tar.gz
  const ok = /^lan-sheriff_<version>_(linux|darwin|windows|freebsd)_(amd64|arm64|arm)(_portable)?\.tar\.gz$/.test(t)
  if (!ok) bad.push(t)
}

if (bad.length) {
  console.error('README names downloads the release does not publish:\n')
  for (const b of bad) console.error(`  ${b}`)
  console.error('\nThe release publishes lan-sheriff_<version>_<os>_<arch>[_portable].tar.gz, and the')
  console.error('binary inside the archive is called lan-sheriff (or lan-sheriff.exe).')
  process.exit(1)
}

// And the other direction: the platforms a person is most likely to arrive for
// must actually be mentioned.
for (const want of ['darwin_arm64', 'darwin_amd64', 'windows_amd64']) {
  if (!tokens.some((t) => t.includes(want))) {
    console.error(`README never names a download for ${want}`)
    process.exit(1)
  }
}

console.log(`downloads: ${new Set(tokens).size} artefact names match what the release builds`)
