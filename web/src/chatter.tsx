import { useCallback, useEffect, useRef, useState } from 'preact/hooks'
import {
  fetchDNS, fetchDNSSummary, fetchTopDomains, fetchNewDomains, fmtAgo,
  message, fetchDevices,
  type DNSEvent, type DNSSummary, type DomainSummary, type Filter,
} from './api'
import { useI18n, fill } from './i18n'
import { visibleInterval } from './visibility'

type Tab = 'feed' | 'top' | 'new'

/**
 * Radio Chatter: the DNS half of the product.
 *
 * The live feed is what people watch; the aggregates are what they act on. "What
 * has this network never asked for before" is a different question from "what
 * does it ask for most", so they are separate tabs rather than one sorted list.
 */
export function Chatter({
  filter, onFilter, layer = '',
}: {
  filter: Filter
  onFilter: (patch: Partial<Filter>) => void
  /** Only ever used to explain itself. Radio Chatter is the one view a peer can
   *  never contribute to: it needs the domains a network looked up, and peer
   *  sharing promises never to transmit those. Rather than quietly showing this
   *  machine's lookups under whatever layer is selected, it says so. */
  layer?: string
}) {
  const { t } = useI18n()
  // **Which device asked.**
  //
  // Every lookup already carries the device that made it, and nothing rendered
  // it, so in Patrol Mode the feed was one undifferentiated stream of domains
  // from every machine on the network with nothing saying whose was whose. That
  // is the question this view exists to answer: not "was this domain looked
  // up" but "who looked it up".
  //
  // The ids are opaque, so they are resolved to the name the Roster shows, the
  // same way the Watchtower resolves them.
  const [deviceNames, setDeviceNames] = useState<Record<string, string>>({})
  useEffect(() => {
    let alive = true
    fetchDevices()
      .then((d) => {
        if (!alive) return
        const m: Record<string, string> = {}
        for (const dev of d.devices ?? []) {
          m[dev.id] = dev.label || dev.name || dev.hostname || dev.ip || dev.id
        }
        setDeviceNames(m)
      })
      .catch(() => {})
    return () => { alive = false }
  }, [])
  const nameOf = (id: string) => deviceNames[id] || id

  const [tab, setTab] = useState<Tab>('feed')
  const [summary, setSummary] = useState<DNSSummary | null>(null)
  const [events, setEvents] = useState<DNSEvent[]>([])
  const [domains, setDomains] = useState<DomainSummary[]>([])
  const [flaggedOnly, setFlaggedOnly] = useState(false)

  const load = useCallback(async () => {
    try {
      setSummary(await fetchDNSSummary(filter))
      if (tab === 'feed') {
        setEvents((await fetchDNS(filter, flaggedOnly)).events)
      } else if (tab === 'top') {
        setDomains((await fetchTopDomains(filter)).domains)
      } else {
        setDomains((await fetchNewDomains(filter)).domains)
      }
    } catch {
      /* the status bar reports connection state; nothing useful to add here */
    }
  }, [filter, tab, flaggedOnly])

  useEffect(() => {
    load()
    // Only the feed needs to be live. Aggregates change slowly and recomputing
    // them every few seconds would be wasted work.
    if (filter.from || tab !== 'feed') return
    return visibleInterval(load, 4000)
  }, [load, filter.from, tab])

  // Render nothing until the capability is known.
  //
  // Without this the component falls through to the full view while `summary` is
  // still null, so a build that cannot see DNS flashes a dashboard of zeroes for
  // a moment before replacing it with the explanation. That reads as the feature
  // breaking rather than as the feature not being available.
  // **Said on every path out of this component, not just the last one.**
  //
  // Radio Chatter is the one view a peer can never contribute to: it needs the
  // domains a network looked up, and peer sharing promises never to transmit
  // those. Placed inside the main return, this explanation was invisible to
  // exactly the reader who needs it most, the one whose build cannot see DNS at
  // all and has just selected a peer to find out what that peer looked up.
  const boundary = layer !== '' && (
    <p class="layer-note">{t.watchtower.layerNoDomains}</p>
  )

  if (!summary) {
    return <div class="chatter-loading" aria-busy="true">{boundary}</div>
  }

  // Nothing to show, and it is worth distinguishing why.
  if (!summary.capable) {
    return (
      <div class="stub">
        {boundary}
        <h2>{t.nav.chatter}</h2>
        <p>{message(t.msg, summary.hint_code, summary.hint ?? t.chatter.needsPatrol)}</p>
        {summary.labelled_domains ? (
          <span class="milestone">
            {fill(t.chatter.listsLoaded, { count: summary.labelled_domains.toLocaleString() })}
          </span>
        ) : null}
      </div>
    )
  }

  return (
    <div class="chatter">
      {boundary}
      <div class="chatter-head panel">
        <div class="chatter-stats">
          <span class="stat"><b>{summary?.stats.lookups ?? 0}</b><span>{t.chatter.lookups}</span></span>
          <span class="stat"><b>{summary?.stats.domains ?? 0}</b><span>{t.chatter.domains}</span></span>
          <span class="stat"><b>{summary?.stats.new_domains ?? 0}</b><span>{t.chatter.newDomains}</span></span>
          <span class="stat flagged">
            <b>{summary?.stats.flagged ?? 0}</b><span>{t.chatter.flagged}</span>
          </span>
        </div>

        <div class="chatter-tabs">
          {(['feed', 'top', 'new'] as Tab[]).map((id) => (
            <button
              key={id}
              class={`range ${tab === id ? 'on' : ''}`}
              onClick={() => setTab(id)}
            >
              {t.chatter[id]}
            </button>
          ))}
          {tab === 'feed' && (
            <label class="chatter-toggle">
              <input
                type="checkbox"
                checked={flaggedOnly}
                onChange={(e) => setFlaggedOnly((e.target as HTMLInputElement).checked)}
              />
              {t.chatter.flaggedOnly}
            </label>
          )}
        </div>
      </div>

      <div class="chatter-body panel">
        {tab === 'feed'
          ? <Feed events={events} onFilter={onFilter} nameOf={nameOf} />
          : <Domains domains={domains} onFilter={onFilter} showNew={tab === 'new'} />}
      </div>
    </div>
  )
}

function Feed({
  events, onFilter, nameOf,
}: {
  events: DNSEvent[]
  onFilter: (patch: Partial<Filter>) => void
  /** Resolves a device id to the name the Roster shows. */
  nameOf: (id: string) => string
}) {
  const { t } = useI18n()
  const listRef = useRef<HTMLDivElement>(null)

  if (events.length === 0) {
    // An empty feed while capture is running reads as a broken product, and it
    // usually is not one. Browsers and Windows send lookups over HTTPS by
    // default now, and reading those would mean intercepting TLS, which this
    // will never do. Saying so is the difference between a limitation and a bug.
    //
    // Only here, not on the domains panel below, which shows the same sentence
    // when it is empty. Printing the explanation twice on one screen is the
    // mistake the Watchtower already made.
    return (
      <div class="list-empty">
        <p>{t.chatter.noLookups}</p>
        <span class="milestone">{t.chatter.noLookupsHint}</span>
      </div>
    )
  }

  return (
    <div class="dns-list" ref={listRef}>
      {events.map((e) => (
        <div class={`dns-row ${e.flagged ? 'flagged' : ''}`} key={e.id}>
          <span class="dns-time">{fmtAgo(e.ts)}</span>
          <button
            class="dns-name"
            title={t.chatter.searchThis}
            onClick={() => onFilter({ q: e.qname })}
          >
            {/* A domain is Latin text in an Arabic page. See app.tsx. */}
            <bdi>{e.qname}</bdi>
          </button>
          {e.flagged && <span class={`dns-tag ${e.flagged}`}>{e.flagged}</span>}
          {/* Who asked. In Deputy Mode this is absent and the row is this
              machine's by definition; in Patrol Mode it is the whole point. */}
          {e.device_id && <span class="dns-device"><bdi>{nameOf(e.device_id)}</bdi></span>}
          {e.process && <span class="dns-proc">{e.process}</span>}
          <span class="dns-type">{e.qtype}</span>
          {/* Nothing at all when there are no answers. The else branch here used
              to be a literal ', ', which put a stray comma at the end of every
              row for a lookup that was never answered, which in production is
              every NXDOMAIN. */}
          {!!e.answers?.length && (
            <span class="dns-answers">{e.answers.slice(0, 2).join(', ')}</span>
          )}
        </div>
      ))}
    </div>
  )
}

function Domains({
  domains, onFilter, showNew,
}: {
  domains: DomainSummary[]
  onFilter: (patch: Partial<Filter>) => void
  showNew: boolean
}) {
  const { t } = useI18n()

  if (domains.length === 0) {
    return <p class="list-empty">{showNew ? t.chatter.noNew : t.chatter.noLookups}</p>
  }

  return (
    <div class="dns-list">
      {domains.map((d) => (
        <div class={`dns-row ${d.flagged ? 'flagged' : ''}`} key={d.domain}>
          <span class="dns-count">{d.lookups}</span>
          <button
            class="dns-name"
            title={t.chatter.searchThis}
            onClick={() => onFilter({ q: d.domain })}
          >
            {d.domain}
          </button>
          {d.flagged && <span class={`dns-tag ${d.flagged}`}>{d.flagged}</span>}
          {d.new && !showNew && <span class="dns-tag new">{t.chatter.newTag}</span>}
          <span class="dns-answers">
            {showNew ? fmtAgo(d.first_seen) : fmtAgo(d.last_seen)}
          </span>
        </div>
      ))}
    </div>
  )
}
