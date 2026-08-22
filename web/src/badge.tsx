/**
 * The sheriff's star, with a network-node motif: the five points are nodes,
 * wired back to a hub at the centre.
 *
 * Five points, not six. A six-pointed star is a hexagram regardless of what
 * else is drawn around it, and this mark should never be mistaken for a
 * religious symbol. Five is also the classic American sheriff's star, so it
 * reads correctly as a badge at favicon size.
 *
 * Drawn rather than an emoji so it scales cleanly, inherits the theme's
 * colours, and can be reused as the favicon and the README mark. The geometry
 * is computed (outer radius 28, inner 12.6, ten alternating vertices) rather
 * than eyeballed.
 */
export function Badge({ size = 26, title = 'LAN Sheriff' }: { size?: number; title?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role="img" aria-label={title} class="badge">
      <defs>
        <linearGradient id="badge-face" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--badge-hi)" />
          <stop offset="100%" stop-color="var(--badge-lo)" />
        </linearGradient>
      </defs>

      <path
        d="M 32 4 L 39.41 21.81 L 58.63 23.35 L 43.98 35.89 L 48.46 54.65
           L 32 44.6 L 15.54 54.65 L 20.02 35.89 L 5.37 23.35 L 24.59 21.81 Z"
        fill="url(#badge-face)"
        stroke="var(--badge-edge)"
        stroke-width="2.4"
        stroke-linejoin="round"
      />

      {/* Links from the hub out to each point: the network inside the badge. */}
      <g stroke="var(--badge-line)" stroke-width="1.5" stroke-linecap="round" opacity="0.8">
        <line x1="32" y1="32" x2="32" y2="12.5" />
        <line x1="32" y1="32" x2="50.55" y2="25.97" />
        <line x1="32" y1="32" x2="43.46" y2="47.78" />
        <line x1="32" y1="32" x2="20.54" y2="47.78" />
        <line x1="32" y1="32" x2="13.45" y2="25.97" />
      </g>

      <g fill="var(--badge-node)">
        <circle cx="32" cy="12.5" r="2.2" />
        <circle cx="50.55" cy="25.97" r="2.2" />
        <circle cx="43.46" cy="47.78" r="2.2" />
        <circle cx="20.54" cy="47.78" r="2.2" />
        <circle cx="13.45" cy="25.97" r="2.2" />
      </g>

      <circle cx="32" cy="32" r="4.6" fill="var(--badge-hub)" stroke="var(--badge-edge)" stroke-width="1.8" />
    </svg>
  )
}
