import { useEffect, useState } from 'preact/hooks'
import { useI18n, fill } from './i18n'
import { message, fetchPlatform, type Capabilities, type Platform } from './api'
import { Command } from './command'

/**
 * The operating system as its makers spell it.
 *
 * Not translated, and not expanded into prose like "64-bit ARM" either. These
 * are proper nouns and machine identifiers: "macOS" is macOS in every language,
 * and "arm64" is the string the reader will match against a file name on the
 * releases page. Turning it into words would make it less useful in the one
 * moment it matters, which is picking a file out of a list of two dozen.
 */
const OS_NAMES: Record<string, string> = {
  darwin: 'macOS',
  linux: 'Linux',
  windows: 'Windows',
  freebsd: 'FreeBSD',
}

function platformLabel(p: Platform): string {
  return `${OS_NAMES[p.os] ?? p.os} · ${p.arch}`
}

/**
 * The Help view.
 *
 * Exists because the only explanation the product offered was a banner about
 * capture modes, reachable through a question mark that did nothing unless you
 * had previously dismissed that banner. Someone who never dismissed it clicked
 * and got silence.
 *
 * Written to answer the questions a person actually arrives with, what is this,
 * what can it see, why is that screen empty, where does my data go, rather than
 * to document the interface. Anything that is obvious from looking at the screen
 * is left out.
 */
export function Help({ mode, caps }: { mode?: string; caps?: Capabilities | null }) {
  const { t } = useI18n()

  // **What this install can see, right now, and the one thing to do about it.**
  //
  // Help opened with what the product is and then explained both modes evenly,
  // leaving a first-time reader to work out which half applied to them. It was
  // also vaguer than the banner it exists to explain: the banner prints an exact
  // command and this said "start it with elevated privileges", naming macOS and
  // Linux and not Windows at all. A tester on Windows had nothing to act on.
  //
  // Every value here was already on the wire and already translated. The hint
  // and the command are the same ones the banner uses, so the two can never
  // disagree.
  const modeName = mode === 'patrol' ? t.status.patrolMode
    : mode === 'offline' ? t.status.offlineMode
    : t.status.deputyMode
  const sees: Array<[boolean, string]> = caps ? [
    [caps.process_attribution, t.help.seeApps],
    [caps.other_devices, t.help.seeDevices],
    [caps.dns_feed, t.help.seeDNS],
    [caps.byte_counts, t.help.seeVolumes],
    [caps.device_inventory, t.help.seeInventory],
  ] : []
  const hint = caps ? message(t.msg, caps.hint_code, caps.hint) : ''

  // Read once. Every field is a property of the running binary, so there is
  // nothing to poll and nothing to invalidate. A failed read simply leaves the
  // facts out rather than showing an error: Help is still worth reading without
  // them, and an error box in the middle of the help page helps nobody.
  const [platform, setPlatform] = useState<Platform | null>(null)
  useEffect(() => {
    let live = true
    fetchPlatform().then(p => { if (live) setPlatform(p) }).catch(() => {})
    return () => { live = false }
  }, [])

  // Which of the three things this binary is. The distinction the reader cares
  // about is not the platform, it is whether Patrol Mode can ever work here,
  // and that has two different negative answers: a portable build on a platform
  // where capture exists (fixable, download the other one) and a platform where
  // no capture build is published at all (not fixable, and saying "download the
  // standard build" would name a file that was never built).
  const buildLine = !platform ? ''
    : platform.capture_built ? t.help.buildStandardIs
    : platform.capture_published ? t.help.buildPortableIs
    : t.help.buildPortableOnlyIs

  return (
    <div class="help panel">
      <div class="help-inner">
      <header class="help-head">
        <h2>{t.help.title}</h2>
        <p>{t.help.subtitle}</p>
      </header>

      {/* **What this install can see right now, and the one thing to do.**

          Help opened with what the product is and then described both modes
          evenly, leaving a first-time reader to work out which half applied to
          them. It was also vaguer than the banner it exists to explain: the
          banner prints an exact command, this said "start it with elevated
          privileges" and named macOS and Linux but not Windows, so a tester on
          Windows had nothing to act on.

          Every value here was already on the wire and already translated. The
          hint and the command are the ones the banner uses, so the two cannot
          disagree. */}
      {caps && (
        <Section title={t.help.startTitle} id="start">
          <p>{fill(t.help.startMode, { mode: modeName })}</p>
          <h4>{t.help.startSees}</h4>
          <ul class="help-caps">
            {sees.map(([on, label]) => (
              <li key={label} class={on ? 'on' : 'off'}>
                <span aria-hidden="true">{on ? '\u2713' : '\u2014'}</span> {label}
              </li>
            ))}
          </ul>
          {hint && (<><h4>{t.help.startDo}</h4><p>{hint}</p></>)}
          {caps.enable_cmd && <Command cmd={caps.enable_cmd} />}

          {/* The facts somebody otherwise leaves for the repository to answer:
              which of the two builds this is, on what, and where the file
              holding everything it has seen actually sits. The database path is
              the one nobody could have guessed, and it is what `lan-sheriff
              status --data-dir` wants. */}
          {platform && (
            <>
              <h4>{t.help.thisTitle}</h4>
              <dl class="help-facts">
                <dt>{t.help.thisPlatform}</dt>
                <dd>{platformLabel(platform)}</dd>
                <dt>{t.help.thisBuild}</dt>
                <dd>{buildLine}</dd>
                <dt>{t.help.thisVersion}</dt>
                {/* bdi: a Latin version beside a number, in a page that is right
                    to left in Arabic and Hebrew. See gate.tsx. */}
                <dd>
                  <bdi>
                    {platform.version}
                    {platform.build && ` \u00b7 ${fill(t.app.build, { n: platform.build })}`}
                    {!platform.distributed && ` (${t.help.buildFromSource})`}
                  </bdi>
                </dd>
                <dt>{t.help.thisDatabase}</dt>
                <dd class="help-path">{platform.db_path}</dd>
              </dl>
            </>
          )}
        </Section>
      )}

      <Section title={t.help.whatTitle}>
        <p>{t.help.whatBody}</p>
      </Section>

      <Section title={t.help.modesTitle} id="modes">
        {/* Each sentence already names its mode, so prefixing it with the mode
            name printed it twice. The mode actually running is marked on the
            paragraph instead, no extra words, and nothing to translate. */}
        <p class={mode === 'deputy' ? 'here' : ''} aria-current={mode === 'deputy' || undefined}>
          {t.help.deputyBody}
        </p>
        <p class={mode === 'patrol' ? 'here' : ''} aria-current={mode === 'patrol' || undefined}>
          {t.help.patrolBody}
        </p>
        <p class="help-aside">{t.help.patrolHow}</p>
      </Section>

      <Section title={t.help.viewsTitle}>
        <dl class="help-views">
          <dt>{t.nav.watchtower}</dt><dd>{t.help.watchtowerBody}</dd>
          <dt>{t.nav.chatter}</dt><dd>{t.help.chatterBody}</dd>
          <dt>{t.nav.precinct}</dt><dd>{t.help.precinctBody}</dd>
          <dt>{t.nav.roster}</dt><dd>{t.help.rosterBody}</dd>
          <dt>{t.nav.wanted}</dt><dd>{t.help.wantedBody}</dd>
        </dl>
      </Section>

      <Section title={t.help.findingsTitle}>
        <p>{t.help.findingsBody}</p>
        <p>{t.help.findingsScore}</p>
        <p>{t.help.findingsActions}</p>
      </Section>

      <Section title={t.help.rulesTitle}>
        {/* Named with the same codes the findings carry, so a rule seen in the
            Wanted List can be looked up here by the words it used. */}
        <dl class="help-rules">
          <dt>{t.rule.new_device}</dt><dd>{t.help.ruleNewDevice}</dd>
          <dt>{t.ruleName.first_contact}</dt><dd>{t.help.ruleFirstContact}</dd>
          <dt>{t.ruleName.beaconing}</dt><dd>{t.help.ruleBeaconing}</dd>
          <dt>{t.ruleName.rare_destination}</dt><dd>{t.help.ruleRareDestination}</dd>
          <dt>{t.ruleName.dga_domain}</dt><dd>{t.help.ruleDga}</dd>
          <dt>{t.ruleName.port_scan}</dt><dd>{t.help.rulePortScan}</dd>
          <dt>{t.ruleName.plaintext}</dt><dd>{t.help.rulePlaintext}</dd>
          <dt>{t.ruleName.volume_anomaly}</dt><dd>{t.help.ruleVolume}</dd>
          <dt>{t.ruleName.threat_list}</dt><dd>{t.help.ruleThreatList}</dd>
        </dl>
        <p class="help-aside">{t.help.rulesQuiet}</p>
      </Section>

      <Section title={t.help.emptyTitle}>
        <p>{t.help.emptyBody}</p>
      </Section>

      <Section title={t.help.trustTitle}>
        <p>{t.help.trustBody}</p>
      </Section>

      <Section title={t.help.privacyTitle}>
        <p>{t.help.privacyBody}</p>

        {/* The complete outbound list, in the product rather than only in
            SECURITY.md. A claim that everything stays on this machine is worth
            no more than the reader's ability to check it, and the file that
            enumerated it was one a user never opens.

            It is also here because the previous wording was not true. It said
            the downloads tell providers "only that someone downloaded a file",
            which holds for the datasets and not for a registration lookup: that
            one sends an address seen on this network, so it says which endpoint
            the user was reading about. That deserves its own paragraph rather
            than a clause, because it is the only item on the list that reveals
            anything. */}
        <h4>{t.help.privacyOutboundTitle}</h4>
        <p>{t.help.privacyOutboundBody}</p>
        <p>{t.help.privacyOutboundRegistration}</p>
        <p>{t.help.privacyOutboundOffline}</p>
        {/* Rendered rather than translated, for the reason given at the sweep
            section below: a literal command is not prose. */}
        <Command cmd="lan-sheriff serve --offline" />

        {/* Stated here whether or not peering is on. Somebody deciding whether
            to enable it needs to read this beforehand, and somebody who never
            enables it is entitled to know what they are declining. */}
        <h4>{t.help.privacyPeeringTitle}</h4>
        <p>{t.help.privacyPeeringBody}</p>
      </Section>

      <Section title={t.help.dataTitle}>
        <p>{t.help.dataBody}</p>
      </Section>

      <Section title={t.help.patrolTitle}>
        <dl class="help-rules">
          <dt>macOS</dt><dd>{t.help.patrolMac}</dd>
          <dt>Linux</dt><dd>{t.help.patrolLinux}</dd>
          <dt>Windows</dt><dd>{t.help.patrolWindows}</dd>
        </dl>
      </Section>

      {/* Everything here was in the README and nowhere the reader could see it,
          which meant the answer to "how do I put this on the other machine"
          was a trip to the repository. The platform the reader is on is listed
          first, because a list of five where one applies is a list somebody has
          to search rather than read. */}
      <Section title={t.help.installTitle} id="install">
        <p>{t.help.installIntro}</p>
        <dl class="help-installs">
          {orderedInstalls(platform, t.help).map(e => (
            <div key={e.label} class="help-install">
              <dt>{e.label}</dt>
              <dd>
                {e.caption && <p>{e.caption}</p>}
                {e.cmds.map(c => <Command key={c} cmd={c} />)}
              </dd>
            </div>
          ))}
        </dl>

        <h4>{t.help.installByHandTitle}</h4>
        <p>{t.help.installByHand}</p>
        {/* Two builds of one program, which is the single most confusing thing
            about the release, so it is a table rather than a paragraph. The
            architecture lists are file-name fragments, not prose. */}
        <table class="help-builds">
          <thead>
            <tr>
              <th />
              <th>{t.help.buildStandard}</th>
              <th>{t.help.buildPortable}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th>{t.status.patrolMode}</th>
              <td>{t.help.buildYes}</td>
              <td>{t.help.buildNoDeputy}</td>
            </tr>
            <tr>
              <th>{t.help.buildNeeds}</th>
              <td>{t.help.buildStandardNeeds}</td>
              <td>{t.help.buildPortableNeeds}</td>
            </tr>
            <tr>
              <th>{t.help.buildBuiltFor}</th>
              <td>Linux amd64 · arm64<br />macOS amd64 · arm64<br />Windows amd64</td>
              <td>Linux amd64 · arm64 · arm<br />Windows amd64 · arm64<br />FreeBSD amd64 · arm64</td>
            </tr>
          </tbody>
        </table>
        <p>{t.help.installPick}</p>
      </Section>

      {/* Pairing is the one feature nobody can work out from the screen alone,
          because the two machines are deliberately given different jobs and
          each shows only its own half. Somebody looking at "Waiting for the
          other machine" has no way to tell from there that the other machine
          is supposed to be typing rather than waiting too. */}
      <Section title={t.help.pairingTitle} id="pairing">
        <p>{t.help.pairingIntro}</p>
        <ol class="help-steps">
          <li>{t.help.pairingStep1}</li>
          <li>{t.help.pairingStep2}</li>
          <li>{t.help.pairingStep3}</li>
        </ol>
        {/* Asked by the first person to own three instances, which will be
            everybody eventually: pairing joins two machines and stops, so the
            arithmetic of who must pair with whom is worth stating before
            somebody assumes it spreads on its own and quietly gets a partial
            picture. */}
        <p>{t.help.pairingReach}</p>
        <p class="help-aside">{t.help.pairingTrouble}</p>
        {/* Named because it is the single hardest pairing failure to diagnose:
            outgoing traffic works, the machine is reachable by every other test
            a person would try, and the pairing port alone is silently dropped.
            It cost an afternoon here before anyone thought to look. */}
        <p class="help-aside">{t.help.pairingTailscale}</p>
      </Section>

      {/* The first thing a headless install does is refuse the connection you
          try from your laptop, which reads as broken software rather than as
          the deliberate default it is. */}
      {/* Updating had no mention anywhere in the product, and two of the three
          platforms have a trap in it that looks like a broken download rather
          than a step the reader skipped: macOS kills a binary copied over its
          predecessor with no message at all, and Linux silently drops the
          capture capability because capabilities belong to the file. Both are
          reported as "the new version is broken", which is the wrong thing for
          a reader to conclude about a tool they are deciding whether to trust. */}
      <Section title={t.help.updateTitle} id="update">
        <p>{t.help.updateBody}</p>
        <p>{t.help.updateMac}</p>
        <Command cmd="rm ~/lan-sheriff && cp ~/Downloads/lan-sheriff ~/lan-sheriff && chmod +x ~/lan-sheriff" />
        <p>{t.help.updateLinux}</p>
        <Command cmd="sudo setcap cap_net_raw,cap_net_admin=eip ./lan-sheriff" />
        <p>{t.help.updateWindows}</p>
        <p>{t.help.updateCheck}</p>
        <Command cmd="lan-sheriff version" />
      </Section>

      <Section title={t.help.remoteTitle} id="remote">
        <p>{t.help.remoteBody}</p>
        <Command cmd="lan-sheriff serve --listen 0.0.0.0:2911 --require-password" />
        <p>{t.help.remotePassword}</p>
      </Section>

      <Section title={t.help.cliTitle} id="cli">
        <p>{t.help.cliBody}</p>
        <p>{t.help.cliStatus}</p>
        <Command cmd="lan-sheriff status" />
        <p>{t.help.cliExport}</p>
        <Command cmd="curl -s 'http://localhost:2911/api/export?view=egress&format=csv' -o destinations.csv" />
        <p class="help-aside">{t.help.cliNoJS}</p>
      </Section>

      {/* Notifications had no interface and no mention anywhere the product
          could be read: four working flags discoverable only by running
          --help, which is not a thing most people do to software that is
          already running and apparently complete. */}
      <Section title={t.help.notifyTitle} id="notifications">
        <p>{t.help.notifyBody}</p>
        <dl class="help-flags">
          <dt><code>--notify-ntfy</code></dt><dd>ntfy</dd>
          <dt><code>--notify-discord</code></dt><dd>Discord</dd>
          <dt><code>--notify-slack</code></dt><dd>Slack</dd>
          <dt><code>--notify-webhook</code></dt><dd>JSON</dd>
        </dl>
        <Command cmd="lan-sheriff serve --notify-ntfy https://ntfy.sh/your-topic" />
        <p class="help-aside">{t.help.notifyScore}</p>
      </Section>

      {/* The flags, in the product rather than only in `--help`. Deliberately
          the short list: a complete reference here would compete with the one
          the binary prints, and the binary's cannot go stale. */}
      <Section title={t.help.optionsTitle} id="options">
        <p>{t.help.optionsIntro}</p>
        <Command cmd="lan-sheriff serve --help" />
        <dl class="help-flags">
          <dt><code>--listen</code></dt><dd>{t.help.optListen}</dd>
          <dt><code>--require-password</code></dt><dd>{t.help.optPassword}</dd>
          <dt><code>--data-dir</code></dt><dd>{t.help.optDataDir}</dd>
          <dt><code>--offline</code></dt><dd>{t.help.optOffline}</dd>
          <dt><code>--city-db</code></dt><dd>{t.help.optCityDB}</dd>
          <dt><code>--interface</code></dt><dd>{t.help.optInterface}</dd>
          <dt><code>--promiscuous=false</code></dt><dd>{t.help.optPromiscuous}</dd>
          <dt><code>--trusted-host</code></dt><dd>{t.help.optProxy}</dd>
        </dl>
      </Section>

      <Section title={t.help.creditsTitle}>
        <p>{t.help.creditsBody}</p>
        {/* Source names, URLs and licence identifiers are not prose. They are
            proper nouns and legal identifiers, identical in every language, and
            putting them in twelve catalogues would risk one being mangled in a
            language nobody on the team reads, with a licence obligation
            attached. Same reasoning as the command blocks. */}
        <dl class="help-views">
          <dt>DB-IP Lite</dt>
          <dd>
            <a href="https://db-ip.com" target="_blank" rel="noreferrer">db-ip.com</a>
            {', CC BY 4.0'}
          </dd>
          <dt>Natural Earth</dt>
          <dd>
            <a href="https://www.naturalearthdata.com" target="_blank" rel="noreferrer">naturalearthdata.com</a>
            {', public domain'}
          </dd>
          <dt>IEEE OUI</dt>
          <dd>{t.help.creditsOUI}</dd>
          <dt>StevenBlack/hosts</dt>
          <dd>
            <a href="https://github.com/StevenBlack/hosts" target="_blank" rel="noreferrer">github.com/StevenBlack/hosts</a>
            {', MIT'}
          </dd>
          <dt>URLhaus</dt>
          <dd>
            <a href="https://urlhaus.abuse.ch" target="_blank" rel="noreferrer">urlhaus.abuse.ch</a>
            {', CC0'}
          </dd>
        </dl>
      </Section>

      <Section title={t.help.sweepTitle}>
        <p>{t.help.sweepBody}</p>
        {/* The flag is rendered here rather than written into twelve
            catalogues: a literal command is not prose, it cannot be translated,
            and putting it in the strings risks it being mangled in a language
            nobody on the team reads. */}
        <Command cmd="lan-sheriff serve --sweep=false" />
      </Section>
      </div>
    </div>
  )
}

function Section({
  title, id, children,
}: {
  title: string
  id?: string
  children: preact.ComponentChildren
}) {
  return (
    <section class="help-section" id={id}>
      <h3>{title}</h3>
      {children}
    </section>
  )
}

/**
 * The install channels, with the reader's own platform first.
 *
 * Ordered rather than filtered. Somebody reading Help on a Pi is often setting
 * up a second machine that is not a Pi, so hiding the others would trade one
 * trip to the repository for another; putting theirs at the top means the
 * common case is answered without scrolling and the rest are still there.
 *
 * The labels and the commands are literals in every language: package managers,
 * distributions and shell commands are typed rather than read.
 */
function orderedInstalls(
  platform: Platform | null,
  h: { installLinuxPkg: string; installOther: string; installDocker: string },
): Array<{ key: string; label: string; caption?: string; cmds: string[] }> {
  const all = [
    { key: 'darwin', label: 'macOS', cmds: ['brew install --cask 291-Group/tap/lan-sheriff'] },
    {
      key: 'windows',
      label: 'Windows',
      cmds: [
        'scoop bucket add 291group https://github.com/291-Group/scoop-bucket',
        'scoop install lan-sheriff',
      ],
    },
    // Arch is deliberately absent. The PKGBUILD exists and the package does
    // not: Arch disabled AUR adoption in July 2026 after a wave of malicious
    // takeovers, so `yay -S lan-sheriff-bin` would fail. Printing a command
    // that cannot work is worse than printing nothing, and install.sh below
    // covers Arch in the meantime.
    {
      key: 'linux',
      label: 'Debian · Ubuntu · Fedora · RHEL · Alpine',
      caption: h.installLinuxPkg,
      cmds: [
        'sudo dpkg -i lan-sheriff_*.deb',
        'sudo rpm -i lan-sheriff-*.rpm',
        'sudo apk add --allow-untrusted lan-sheriff_*.apk',
      ],
    },
    {
      key: 'any',
      label: 'Raspberry Pi · FreeBSD · anything else',
      caption: h.installOther,
      cmds: ['curl -fsSL https://raw.githubusercontent.com/291-Group/LAN-Sheriff/main/install.sh | sh'],
    },
    { key: 'docker', label: 'Docker', caption: h.installDocker, cmds: ['docker compose up -d'] },
  ]
  if (!platform) return all
  // Stable partition: the reader's platform keeps its internal order, and so
  // does everything else, so the list does not reshuffle between platforms in
  // ways that would make it hard to describe.
  const mine = all.filter(e => e.key === platform.os)
  return [...mine, ...all.filter(e => !mine.includes(e))]
}
