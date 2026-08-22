import { useEffect, useRef, useState } from 'preact/hooks'
import { search as runSearch, exportUrl, type Filter, type SearchResult } from './api'
import { useI18n, fill } from './i18n'

const RANGES: { id: string; label: string }[] = [
  { id: '15m', label: '15m' },
  { id: '1h', label: '1h' },
  { id: '6h', label: '6h' },
  { id: '24h', label: '24h' },
  { id: '7d', label: '7d' },
  { id: '30d', label: '30d' },
]

/**
 * The filter bar sits above every view. Narrowing here narrows everywhere,
 * which is what makes this one tool rather than several.
 */
export function Toolbar({
  filter, onChange, view, layer = '',
}: {
  filter: Filter
  onChange: (f: Filter) => void
  view: string
  /** Which machines to search. Search read only this machine's tables whatever
   *  the dashboard was showing, so an organization a peer had contacted could
   *  be visible on the map and unfindable by typing its name. */
  layer?: string
}) {
  const { t } = useI18n()
  const set = (patch: Partial<Filter>) => onChange({ ...filter, ...patch })

  // Choosing a relative range clears any explicit window the scrub left behind.
  const setRange = (range: string) => onChange({ ...filter, range, from: undefined, to: undefined })

  const chips: { label: string; clear: () => void }[] = []
  if (filter.process)
    chips.push({ label: fill(t.toolbar.filterApp, { value: filter.process }), clear: () => set({ process: undefined }) })
  if (filter.country)
    chips.push({ label: fill(t.toolbar.filterCountry, { value: filter.country }), clear: () => set({ country: undefined }) })
  if (filter.org)
    chips.push({ label: fill(t.toolbar.filterOrg, { value: filter.org }), clear: () => set({ org: undefined }) })
  if (filter.proto)
    chips.push({ label: fill(t.toolbar.filterProto, { value: filter.proto }), clear: () => set({ proto: undefined }) })
  if (filter.port)
    chips.push({ label: fill(t.toolbar.filterPort, { value: filter.port }), clear: () => set({ port: undefined }) })
  if (filter.q)
    chips.push({ label: `\u201c${filter.q}\u201d`, clear: () => set({ q: undefined }) })

  return (
    <div class="toolbar">
      <div class="ranges" role="group" aria-label={t.toolbar.timeRange}>
        {RANGES.map((r) => (
          <button
            key={r.id}
            class={`range ${!filter.from && filter.range === r.id ? 'on' : ''}`}
            onClick={() => setRange(r.id)}
          >
            {r.label}
          </button>
        ))}
        {filter.from && (
          <button class="range on" onClick={() => setRange(filter.range)} title={t.toolbar.backToLive}>
            {t.toolbar.scrubbed}
          </button>
        )}
      </div>

      <SearchBox filter={filter} onChange={onChange} layer={layer} />

      {chips.length > 0 && (
        <div class="chips">
          {chips.map((c) => (
            <button key={c.label} class="filter-chip" onClick={c.clear} title={t.toolbar.removeFilter}>
              {c.label}
              <span aria-hidden="true">×</span>
            </button>
          ))}
          {chips.length > 1 && (
            <button
              class="filter-chip clear-all"
              onClick={() => onChange({ range: filter.range, from: filter.from, to: filter.to })}
            >
              {t.toolbar.clearAll}
            </button>
          )}
        </div>
      )}

      <div class="toolbar-right">
        <a class="ghost-btn" href={exportUrl(filter, view, 'csv')} download title={t.toolbar.exportCsv}>
          CSV
        </a>
        <a class="ghost-btn" href={exportUrl(filter, view, 'json')} download title={t.toolbar.exportJson}>
          JSON
        </a>
      </div>
    </div>
  )
}

/**
 * Global search across destinations, organizations, applications and countries.
 * Picking a result sets the corresponding filter rather than navigating, so the
 * user stays in whatever view they were already looking at.
 */
function SearchBox({ filter, onChange, layer }: { filter: Filter; onChange: (f: Filter) => void; layer: string }) {
  const { t } = useI18n()
  const [term, setTerm] = useState('')
  const [results, setResults] = useState<SearchResult[]>([])
  const [open, setOpen] = useState(false)
  const boxRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (term.trim().length < 2) {
      setResults([])
      return
    }
    // Debounced: a query per keystroke would hammer the database for nothing.
    const t = setTimeout(async () => {
      try {
        const r = await runSearch(term, layer)
        setResults(r.results)
        setOpen(true)
      } catch {
        setResults([])
      }
    }, 180)
    return () => clearTimeout(t)
  }, [term])

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])

  const pick = (r: SearchResult) => {
    const patch: Partial<Filter> = {}
    if (r.kind === 'org') patch.org = r.key
    else if (r.kind === 'process') patch.process = r.key
    else if (r.kind === 'country') patch.country = r.key
    else patch.q = r.key
    onChange({ ...filter, ...patch })
    setTerm('')
    setResults([])
    setOpen(false)
  }

  return (
    <div class="searchbox" ref={boxRef}>
      <input
        type="search"
        placeholder={t.toolbar.searchPlaceholder}
        value={term}
        onInput={(e) => setTerm((e.target as HTMLInputElement).value)}
        onFocus={() => results.length && setOpen(true)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') { setOpen(false); setTerm('') }
          if (e.key === 'Enter' && term.trim()) {
            onChange({ ...filter, q: term.trim() })
            setTerm(''); setOpen(false)
          }
        }}
      />
      {open && results.length > 0 && (
        <div class="results">
          {results.map((r) => (
            <button key={`${r.kind}:${r.key}:${r.peer ?? ''}`} class="result" onClick={() => pick(r)}>
              <span class="result-kind">{r.kind}</span>
              <span class="result-label">{r.label}</span>
              {/* **What tells two hits apart.** An endpoint is labelled with the
                  organization that owns it, so a search for "cloud" returned ten
                  rows all reading "Cloudflare, Inc." and differing only in a
                  number, with no way to know which address you were about to
                  filter on. The address is what makes them distinct and it was
                  already on the wire, in `key`, being used only for the React
                  key. Shown for endpoints alone: for an org the key and the
                  label are the same string, and printing it twice explains
                  nothing. */}
              {r.kind === 'endpoint' && r.key !== r.label && (
                <span class="result-addr">{r.key}</span>
              )}
              {/* Which machine saw it. A hit from a peer must never be mistaken
                  for one of this machine's own: the counts come from somebody
                  else's network and cannot be filtered on here. */}
              {r.peer && <span class="result-peer">{r.peer}</span>}
              <span class="result-count">{r.count}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
