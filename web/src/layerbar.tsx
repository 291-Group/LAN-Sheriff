import { useI18n } from './i18n'
import { fingerprint, type PeerState } from './api'

/**
 * Which machines a view is showing: this one, one peer, or everything.
 *
 * # Why this is in the shell and not in a view
 *
 * It used to live inside the Watchtower, and so did the whole idea of peer data.
 * Turning on The Dispatch changed one view out of five and left the rest reading
 * this machine's tables in silence. Somebody who paired two houses, watched
 * another machine's traffic appear on the map, and then opened the Precinct Map
 * or the Roster expecting the same, got their own network with nothing on screen
 * to say why.
 *
 * That is not a missing feature in four views, it is one design mistake made
 * once: peering is a property of the whole dashboard and was built as a property
 * of one view. So the control moves up here, every view that can answer for a
 * layer receives it, and the one view that can never answer for it says so out
 * loud instead of quietly showing something else.
 *
 * Hidden entirely when there is nothing to choose between, which is the
 * overwhelmingly common case: peering off, or on with nobody paired.
 */
export function LayerBar({
  peers, layer, onChange,
}: {
  peers: PeerState[]
  layer: string
  onChange: (layer: string) => void
}) {
  const { t } = useI18n()
  if (peers.length === 0) return null

  return (
    <div class="layerbar" role="group" aria-label={t.watchtower.layersLabel}>
      <button class={layer === '' ? 'on' : ''} onClick={() => onChange('')}>
        {t.watchtower.layerMine}
      </button>
      {peers.map((p) => (
        <button
          key={p.peer_id}
          class={layer === p.peer_id ? 'on' : ''}
          onClick={() => onChange(p.peer_id)}
          // fingerprint(), not the raw id. An unlabelled peer was rendered
          // here as 25 unbroken characters, while every other place in the
          // product shows the same machine as five groups of five. Same value,
          // two spellings, and the reader has no way to know that.
          title={p.label || fingerprint(p.peer_id)}
        >
          {p.label || fingerprint(p.peer_id)}
        </button>
      ))}
      <button class={layer === 'all' ? 'on' : ''} onClick={() => onChange('all')}>
        {t.watchtower.layerAll}
      </button>
    </div>
  )
}
