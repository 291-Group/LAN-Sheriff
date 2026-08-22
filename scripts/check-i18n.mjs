#!/usr/bin/env node
// Checks the translation catalogues for defects a type system cannot see.
//
// TypeScript already guarantees every language has every key, a missing one
// fails the build. What it cannot see is a string that is present but wrong, and
// the failure that prompted this was exactly that: a Hebrew string reading
// "טלמetriה", with Latin letters spliced into the middle of the word. It renders,
// it type-checks, and only a reader of that language would notice.
//
// Two checks:
//   1. No stray Latin runs inside a non-Latin catalogue, beyond an allowlist of
//      product and protocol names that legitimately stay in Latin script.
//   2. No stray non-Latin characters inside a Latin catalogue.
//
// Neither replaces review by a native speaker before launch. They catch the
// mechanical damage that creeps in when strings are edited in bulk.

import { readFileSync, readdirSync } from 'node:fs'

const DIR = new URL('../web/src/i18n/', import.meta.url)

// Names that stay in Latin script in every language.
const ALLOWED = new Set([
  'LAN', 'Sheriff', 'Group', 'DNS', 'DHCP', 'IP', 'IPP', 'UPnP', 'mDNS', 'SSDP',
  'AS', 'TCP', 'UDP', 'HTTP', 'HTTPS', 'CDN', 'MAC', 'OS', 'macOS', 'Linux',
  'Windows', 'CSV', 'JSON', 'MB', 'GB', 'KB', 'bcrypt', 'PBC', 'LLC', 'Inc',
  'ltr', 'rtl', 'en',
  // Capture stack names that stay in Latin in every language.
  'BPF', 'Npcap', 'libpcap',
  // Product and platform names. "Raspberry Pi" is the hardware as its makers
  // spell it, and "JavaScript" is the language: both are proper nouns that stay
  // Latin in every catalogue, the same as macOS and Windows above.
  'JavaScript', 'Raspberry', 'Pi',
  // Distributions, projects and products, named the way their makers name them.
  // A translated distribution name is a name the reader cannot match against a
  // download page or a package manager, which is the moment these appear.
  'Debian', 'Ubuntu', 'Fedora', 'RHEL', 'Alpine', 'Arch', 'Docker',
  'FreeBSD', 'pfSense', 'OPNsense', 'ARM',
  // Named in the pairing diagnostics: its "block incoming" setting discards
  // inbound traffic on every interface, which is otherwise near-undiagnosable.
  // The product and its network are proper nouns; the setting name is
  // translated like any other prose.
  'Tailscale', 'tailnet',
  // The superuser account and the command that borrows it, both typed exactly
  // as spelled on every system.
  'root', 'sudo',
  // The Linux service manager and the exact spelling of the unit setting a
  // reader has to type into a file. Translating either would produce something
  // that cannot be typed anywhere.
  'systemd', 'AmbientCapabilities',
  // Keys as they are printed on the keyboard, which is the same in every
  // language a keyboard is sold in.
  'Ctrl', 'V',
  // Protocol names, which stay in Latin in every language.
  'Telnet', 'FTP', 'SFTP', 'SSH', 'VNC', 'LDAP', 'SMB', 'IMAP', 'POP3', 'SMTP', 'NTP', 'RDP',
  'TLS', 'VPN', 'Host',
  // A command-line flag the reader has to type exactly, so it stays Latin in
  // every language for the same reason a file path would.
  'interface',
])

const NON_LATIN = new Set(['ru', 'ja', 'zh', 'hi', 'bn', 'ar', 'he'])
const LATIN = new Set(['en', 'fr', 'es', 'de', 'pt'])

// Blocks belonging to the non-Latin catalogues.
const FOREIGN = /[Ѐ-ӿ֐-׿؀-ۿऀ-ॿঀ-৿぀-ヿ一-鿿]/

let failed = false

for (const file of readdirSync(DIR).filter((f) => f.endsWith('.ts') && f !== 'index.tsx')) {
  const lang = file.replace(/\.ts$/, '')
  const src = readFileSync(new URL(file, DIR), 'utf8')

  for (const m of src.matchAll(/'((?:[^'\\]|\\.)*)'/g)) {
    // Placeholders are code, not prose. The character class includes the
    // underscore: {known_orgs} and {share_pct} are as much placeholders as
    // {count}, and omitting it reported every one of them as damage.
    const value = m[1].replace(/\{[a-zA-Z_][a-zA-Z0-9_]*\}/g, '')

    if (NON_LATIN.has(lang)) {
      // A Latin run is only suspicious when it sits against non-Latin text: a
      // wholly Latin value is a type code or an identifier.
      if (!FOREIGN.test(value)) continue
      // A URL is never translated, and scanning one produces nothing but noise:
      // "https", the host and the TLD each read as a stray Latin run inside
      // otherwise non-Latin text. Stripped rather than allowlisted, because
      // allowing "https" and "com" everywhere would blind the check to real
      // damage that happens to contain them.
      let prose = value.replace(/https?:\/\/\S+/g, ' ')
      // Query parameters the reader has to type exactly, such as format=json
      // and view=flows. Stripped for the same reason a URL is: they are
      // literals rather than prose, and allowlisting the individual words
      // "view", "format" and "flows" would blind the check to a real bulk-edit
      // accident that happened to use one of them.
      prose = prose.replace(/\b[a-zA-Z_]+=[a-zA-Z0-9_.-]+/g, ' ')
      // Unicode escapes, which are markup rather than prose. The bidi isolates
      // around a Latin product name in an RTL string are written as U+2066 and
      // U+2069 rather than as the characters themselves, so that a reviewer can
      // see them at all: an invisible character sitting in a source file is
      // exactly the kind of damage this script exists to catch, and writing one
      // deliberately should not mean hiding it. Scanning the escape reports its
      // "u" as a stray Latin run, which is the check misreading house style.
      prose = prose.replace(/\\u[0-9a-fA-F]{4}/g, ' ')
      for (const run of prose.match(/[A-Za-z]+/g) ?? []) {
        if (!ALLOWED.has(run)) {
          console.error(`${file}: Latin "${run}" inside translated text: ${value.slice(0, 60)}`)
          failed = true
        }
      }
    } else if (LATIN.has(lang)) {
      if (FOREIGN.test(value)) {
        console.error(`${file}: non-Latin characters in a Latin-script catalogue: ${value.slice(0, 60)}`)
        failed = true
      }
    }
  }
}

if (failed) {
  console.error('\nThese are almost always damage from a bulk edit. Fix them, or add a genuine product name to the allowlist.')
  process.exit(1)
}
console.log('i18n catalogues: no mixed-script damage')
