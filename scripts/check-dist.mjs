// Fails if the committed dashboard bundle does not match the sources it is
// built from.
//
// internal/web/dist is committed on purpose, so that `go install` and `go
// build` work with no Node anywhere. The cost of that decision is a build
// artefact under version control, and the one thing those do is fall behind.
//
// It did. The fix for the blank dashboard went in as a source change and the
// rebuilt bundle was left unstaged, so the tree carried a dashboard without the
// fix. Every local `make build` regenerated a correct one, which is why nothing
// looked wrong: only somebody installing straight from the repository would
// have got it, and what they would have got is the bug.
//
// # Why this asks git rather than the filesystem
//
// The first version compared modification times, which is right in a working
// tree and meaningless in a clone: `git checkout` writes every file at once, so
// a fresh clone had 0.042 seconds between the newest source and the newest
// artefact and which one won was a coin toss. Half of everybody who cloned the
// repository and ran `make check` would have been told to rebuild a bundle that
// was perfectly current.
//
// Commit time is the honest question anyway. "Was dist rebuilt after the
// sources changed" is a question about history, not about when files happened
// to be written to this disk. `git log -1` answers it identically in a clone, a
// worktree and CI.
//
// Outside a git repository, or with either path never committed, it falls back
// to mtimes with a tolerance wide enough that a checkout cannot trip it.
import { existsSync, readdirSync, statSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'

const DIST = 'internal/web/dist'
const SOURCES = ['web/src', 'web/public', 'web/index.html', 'web/package.json']

if (!existsSync(DIST)) {
  console.error(`no ${DIST}; run: make web`)
  process.exit(1)
}

/** Unix time of the last commit that touched any of these paths, or 0. */
function lastCommit(paths) {
  const present = paths.filter((p) => existsSync(p))
  if (present.length === 0) return 0
  try {
    const out = execFileSync(
      'git', ['log', '-1', '--format=%ct', '--', ...present],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim()
    return out ? Number(out) : 0
  } catch {
    return 0 // not a git repository, or git is not installed
  }
}

const srcCommit = lastCommit(SOURCES)
const distCommit = lastCommit([DIST])

if (srcCommit && distCommit) {
  if (srcCommit > distCommit) {
    console.error('the committed dashboard is older than its sources.')
    console.error(`  sources last committed: ${new Date(srcCommit * 1000).toISOString()}`)
    console.error(`  bundle  last committed: ${new Date(distCommit * 1000).toISOString()}`)
    console.error('run: make web   then commit internal/web/dist')
    process.exit(1)
  }
  console.log('dashboard bundle: committed no earlier than its sources')
  process.exit(0)
}

// Fall back to the filesystem, for a tree that is not in git yet.
const newest = (dir) => {
  let t = 0
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name)
      if (e.isDirectory()) walk(p)
      else t = Math.max(t, statSync(p).mtimeMs)
    }
  }
  if (statSync(dir).isDirectory()) walk(dir)
  else t = statSync(dir).mtimeMs
  return t
}

const src = Math.max(...SOURCES.filter(existsSync).map(newest), 0)
const built = newest(DIST)

// A checkout writes everything within the same moment, so anything under a
// couple of seconds is the filesystem talking rather than a stale bundle.
const TOLERANCE_MS = 5000

if (src - built > TOLERANCE_MS) {
  console.error('the committed dashboard is older than its sources.')
  console.error('run: make web   then commit internal/web/dist')
  process.exit(1)
}
console.log('dashboard bundle: no older than its sources')
