import { useEffect, useState } from 'preact/hooks'
import { createPortal } from 'preact/compat'
import {
  fetchDispatch, setPeering, startPairing, cancelPairing, joinWithCode,
  setPeerTrust, unpairPeer, renamePeer, fmtAgo, fingerprint, shortFingerprint, ApiError,
  type DispatchState, type PairingCode, type PeerState,
} from './api'
import { useI18n, fill } from './i18n'
import { CopyButton, PasteButton, slug } from './clip'
import { visibleInterval } from './visibility'

/**
 * The Dispatch panel: this instance's identity, its peers, and pairing.
 *
 * Lives inside Settings rather than earning a nav item. Peering is off by
 * default and most people will never turn it on; a permanent entry in the main
 * navigation would advertise a feature that is usually absent, and the whole
 * point of the default is that nothing leaves the machine.
 *
 * Written so that the *off* state is a complete answer rather than an empty
 * screen. Somebody who opens this without peering enabled should learn what it
 * is and how to turn it on, not see a blank list.
 */
/**
 * Formats a pairing code as it is typed.
 *
 * # Why this is worth the code
 *
 * The code is forty characters in eight groups, and the protocol allows **one
 * attempt per code**. So a single mistyped character does not produce a retry,
 * it burns the pairing window and sends the reader back to the other machine
 * for a fresh code. The five minute expiry gets blamed for that, but the clock
 * is rarely the thing that ran out: the typing was.
 *
 * Every transformation here matches ParseJoinCode on the server exactly, so
 * what somebody sees while typing is what the far end will read:
 *
 *   - separators and spaces are dropped, then re-inserted every five
 *     characters, so pasting a code with dashes, without them, or with spaces
 *     all look identical once typed;
 *   - case is folded up;
 *   - I and L become 1, and O becomes 0, which are the substitutions a person
 *     copying from a screen actually makes;
 *   - anything outside the alphabet is discarded rather than shown, because a
 *     character the server will reject should never reach it.
 *
 * Crockford base32 omits I, L, O and U by design, for exactly this reason.
 */
const CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const CODE_CHARS = 40
const CODE_GROUP = 5

export function formatJoinCode(input: string): string {
  let out = ''
  for (const raw of input.toUpperCase()) {
    let ch = raw
    if (ch === 'I' || ch === 'L') ch = '1'
    else if (ch === 'O') ch = '0'
    if (!CODE_ALPHABET.includes(ch)) continue
    out += ch
    if (out.length === CODE_CHARS) break
  }
  const groups: string[] = []
  for (let i = 0; i < out.length; i += CODE_GROUP) {
    groups.push(out.slice(i, i + CODE_GROUP))
  }
  return groups.join('-')
}

/**
 * Where the caret belongs after the code has been regrouped.
 *
 * # Why this is needed at all
 *
 * The input reformats on every keystroke, and writing a new string into a text
 * field puts the caret at the end of it. That is invisible while you are typing
 * forwards, because the end is where the caret already was. It is intolerable
 * the moment you go back to fix a typo: one character in, and the caret jumps
 * to the end of forty. Correcting the fifth character meant deleting the
 * thirty-five after it, and the code has to be typed by hand from another
 * screen, so a typo is not the unusual case.
 *
 * Counting is done in code characters rather than string offsets, because the
 * dashes are inserted by us and move as the text grows. Everything before the
 * caret is folded exactly as formatJoinCode folds it; whatever survives is how
 * many real characters precede the caret, and that number is stable across the
 * reformat even though the offset is not.
 */
export function caretAfterFormat(raw: string, caret: number): number {
  let n = 0
  for (const ch of raw.slice(0, caret).toUpperCase()) {
    let c = ch
    if (c === 'I' || c === 'L') c = '1'
    else if (c === 'O') c = '0'
    if (CODE_ALPHABET.includes(c)) n++
  }
  if (n > CODE_CHARS) n = CODE_CHARS
  if (n === 0) return 0
  // One dash for every complete group that ends before this point.
  return n + Math.floor((n - 1) / CODE_GROUP)
}

/** How many characters of the code are still missing. */
/**
 * A countdown a person can read at a glance.
 *
 * This printed raw seconds, survivable at a five minute window and absurd at
 * fifteen: "Expires in 900s" is a stopwatch reading rather than a deadline, and
 * nobody divides by sixty while transcribing forty characters onto another
 * machine. Minutes and seconds, zero padded, so the width does not jitter as it
 * counts down.
 */
export function countdown(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

export function joinCodeRemaining(formatted: string): number {
  return CODE_CHARS - formatted.replace(/-/g, '').length
}

export function DispatchPanel() {
  const { t } = useI18n()
  const [state, setState] = useState<DispatchState | null>(null)
  const [pairing, setPairing] = useState<PairingCode | null>(null)
  // How many peers existed when the code was displayed. The pairing itself
  // completes on the *other* machine, so this side finds out by noticing a new
  // peer, without it the screen sits on "waiting" after it has already worked,
  // which is what it did.
  const [pairBaseline, setPairBaseline] = useState(0)
  const [joining, setJoining] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const refresh = () =>
    fetchDispatch()
      .then((d) => {
        setState(d)
        setPairing((open) => (open && d.peers.length > pairBaseline ? null : open))
        return d
      })
      .catch(() => {})
  useEffect(() => {
    refresh()
    // Peer state changes on its own (a laptop closes, a peer reconnects) so
    // this polls while the panel is open. Cheap: it reads memory and one table.
    return visibleInterval(refresh, 4000)
  }, [pairBaseline])

  if (!state) return null

  if (!state.enabled) {
    return (
      <section class="dispatch">
        <h3>{t.dispatch.title}</h3>
        <p class="modal-note"><strong>{t.dispatch.offTitle}</strong></p>
        <p class="modal-note">{t.dispatch.offBody}</p>
        {error && <p class="gate-error">{error}</p>}
        {/* Turning this on shares nothing by itself, no peer exists until a
            code is carried between two machines, so the button says what it
            actually does rather than warning about something that has not
            happened yet. */}
        <button type="button"
          class="primary-btn"
          disabled={busy}
          onClick={async () => {
            setError(''); setBusy(true)
            try {
              await setPeering(true)
              await refresh()
            } catch (e) {
              setError(e instanceof Error ? e.message : String(e))
            } finally {
              setBusy(false)
            }
          }}
        >
          {t.dispatch.turnOn}
        </button>
      </section>
    )
  }

  return (
    <section class="dispatch">
      <h3>{t.dispatch.title}</h3>

      <dl class="modal-facts">
        <dt>{t.dispatch.thisMachine}</dt>
        <dd><code class="peer-id">{fingerprint(state.peer_id)}</code></dd>
        {state.listen && (<>
          <dt>{t.dispatch.reachableAt}</dt>
          <dd><code>{state.listen}</code></dd>
        </>)}
      </dl>

      {error && <p class="gate-error">{error}</p>}

      {state.peers.length === 0 ? (
        <p class="modal-note">
          {t.dispatch.noPeers} {t.dispatch.noPeersHint}
        </p>
      ) : (
        <ul class="peer-list">
          {state.peers.map((p) => (
            <Peer
              key={p.peer_id}
              peer={p}
              onChanged={refresh}
              onError={(e) => setError(e)}
            />
          ))}
        </ul>
      )}

      {/* **Two machines, two different buttons, said out loud.**

          This read as one obvious primary action with a lesser option beneath
          it, so two people at two machines both pressed the big one, both got
          a code, and both ended up on a dialog with nothing to type into.
          Neither had done the half that needs typing, and nothing on screen
          said the two halves existed. */}
      <p class="modal-note pair-roles">{t.dispatch.pairRoles}</p>
      <div class="peer-actions">
        <button type="button"
          class="btn"
          onClick={async () => {
            setError('')
            try {
              setPairBaseline(state.peers.length)
              setPairing(await startPairing())
            } catch (e) {
              setError((e as Error).message)
            }
          }}
        >
          {t.dispatch.pairButton}
        </button>
        {/* Equal weight. The half somebody has to find is not the lesser half. */}
        <button type="button" class="btn" onClick={() => { setError(''); setJoining(true) }}>
          {t.dispatch.joinButton}
        </button>
      </div>

      {pairing && (
        <ShowCode
          code={pairing}
          onNew={async () => {
            // StartPairing refuses while a window is open, so the dead one is
            // closed before asking for its replacement.
            setError('')
            try {
              await cancelPairing().catch(() => {})
              setPairBaseline(state.peers.length)
              setPairing(await startPairing())
            } catch (e) {
              setError((e as Error).message)
              setPairing(null)
            }
          }}
          onClose={() => {
            // Closing the screen closes the window. A code that outlives the
            // screen showing it is a credential nobody is watching.
            cancelPairing().catch(() => {})
            setPairing(null)
            refresh()
          }}
        />
      )}
      {joining && (
        <EnterCode onClose={() => { setJoining(false); refresh() }} />
      )}

      {/* Switching sharing off keeps existing pairings. Stopping and unpairing
          are different decisions, and conflating them would quietly discard
          peers somebody went to the trouble of establishing. */}
      <p class="modal-note dispatch-off-note">
        <button type="button"
          class="ghost-btn"
          disabled={busy}
          onClick={async () => {
            setError(''); setBusy(true)
            try {
              await setPeering(false)
              await refresh()
            } catch (e) {
              setError(e instanceof Error ? e.message : String(e))
            } finally {
              setBusy(false)
            }
          }}
        >
          {t.dispatch.turnOff}
        </button>
      </p>
    </section>
  )
}

/** One paired machine, with the two things you can do to it. */
function Peer({ peer, onChanged, onError }: {
  peer: PeerState
  onChanged: () => void
  onError: (e: string) => void
}) {
  const { t } = useI18n()
  const [confirming, setConfirming] = useState(false)
  const [renaming, setRenaming] = useState(false)
  const [draft, setDraft] = useState(peer.label ?? '')

  const status =
    peer.status === 'suspended' ? t.dispatch.suspended
    : peer.status === 'connected' ? t.dispatch.connected
    : t.dispatch.unreachable

  const act = async (fn: () => Promise<void>) => {
    try {
      await fn()
      onChanged()
    } catch (e) {
      onError((e as Error).message)
    }
  }

  return (
    <li class={`peer peer-${peer.status}`}>
      <div class="peer-head">
        <span class="presence" aria-hidden="true" />
        {/* **Named, or nameable.** A machine that cannot describe itself is not
            unusual: a container's hostname is its own id, and a machine nobody
            has renamed is "localhost". Both reach us as no name at all, and
            without this button the peer would be a fingerprint forever. The
            short form stands in meanwhile, because the full twenty-nine
            characters wrap to two lines and read as though the machine really
            were called that. */}
        {renaming ? (
          <form
            class="peer-rename"
            onSubmit={(e) => {
              e.preventDefault()
              act(async () => { await renamePeer(peer.peer_id, draft); setRenaming(false) })
            }}
          >
            <input
              value={draft}
              autoFocus
              maxLength={40}
              placeholder={t.dispatch.namePlaceholder}
              aria-label={t.dispatch.nameThis}
              onInput={(e) => setDraft((e.target as HTMLInputElement).value)}
            />
            <button type="submit" class="ghost-btn">{t.actions.save}</button>
            <button type="button" class="ghost-btn"
              onClick={() => { setDraft(peer.label ?? ''); setRenaming(false) }}
            >{t.actions.cancel}</button>
          </form>
        ) : (
          <>
            <strong>{peer.label || shortFingerprint(peer.peer_id)}</strong>
            {/* A pencil rather than the words, because the words are as wide as
                the name beside them: at full text the status wrapped onto its
                own line for any peer whose name was long, and the two cards
                stopped lining up. The sentence lives in the label, where a
                screen reader and a tooltip both find it. */}
            <button type="button" class="peer-rename-btn"
              title={t.dispatch.nameThis}
              aria-label={t.dispatch.nameThis}
              onClick={() => { setDraft(peer.label ?? ''); setRenaming(true) }}
            >{'\u270e'}</button>
            <span class="peer-status">{status}</span>
          </>
        )}
      </div>
      <div class="peer-meta">
        {/* Only when there is a name above it. Without a label the heading is
            already the fingerprint, and this printed the same 29 characters
            twice, one under the other, which reads as two different facts. */}
          <code class="peer-id">{fingerprint(peer.peer_id)}</code>
        {peer.addr && <code>{peer.addr}</code>}
        <span>
          {peer.last_seen && !peer.last_seen.startsWith('0001')
            ? fill(t.dispatch.lastSeen, { when: fmtAgo(peer.last_seen) })
            : t.dispatch.neverSeen}
        </span>
        {/* Said separately from the status: a peer can be connected with
            nothing recent to show, or unreachable with a good last hour. */}
        {peer.data_stale && peer.status !== 'suspended' && (
          <span class="peer-stale">{t.dispatch.stale}</span>
        )}
      </div>

      {confirming ? (
        <div class="danger-actions">
          <p class="modal-note">{t.dispatch.unpairHint}</p>
          <button type="button"
            class="btn-danger"
            onClick={() => act(async () => { await unpairPeer(peer.peer_id); setConfirming(false) })}
          >
            {t.dispatch.confirm}
          </button>
          <button type="button" class="ghost-btn" onClick={() => setConfirming(false)}>
            {t.actions.cancel}
          </button>
        </div>
      ) : (
        <div class="peer-buttons">
          {peer.status === 'suspended' ? (
            <button type="button" class="ghost-btn" onClick={() => act(() => setPeerTrust(peer.peer_id, 'trusted'))}>
              {t.dispatch.resume}
            </button>
          ) : (
            <button type="button"
              class="ghost-btn"
              title={t.dispatch.suspendHint}
              onClick={() => act(() => setPeerTrust(peer.peer_id, 'suspended'))}
            >
              {t.dispatch.suspend}
            </button>
          )}
          <button type="button" class="ghost-btn" onClick={() => setConfirming(true)}>
            {t.dispatch.unpair}
          </button>
        </div>
      )}
    </li>
  )
}

/**
 * Freezes whatever is behind a dialog while it is open.
 *
 * The pairing dialogs are portalled to <body>, so their backdrop covers the
 * viewport, and that alone was not enough: the settings modal underneath still
 * scrolled. Scrolling it moved content out from behind the blurred area and
 * left it sharp and readable, which is how "Delete everything" ended up legible
 * under a dialog showing a pairing code. Covering a thing is not the same as
 * stopping it moving.
 *
 * Applied to the whole document rather than to one element, because the dialog
 * no longer sits inside the thing it needs to freeze.
 */
function useScrollLock() {
  useEffect(() => {
    const root = document.documentElement
    root.classList.add('dialog-open')
    return () => root.classList.remove('dialog-open')
  }, [])
}

/** The displaying side: a code to carry to the other machine. */
function ShowCode(
  { code, onNew, onClose }:
  { code: PairingCode; onNew: () => void; onClose: () => void },
) {
  const [confirmClose, setConfirmClose] = useState(false)
  const { t } = useI18n()
  useScrollLock()
  const [left, setLeft] = useState(() =>
    Math.max(0, Math.round((new Date(code.expires_at).getTime() - Date.now()) / 1000)))

  useEffect(() => {
    // Safe to pause off screen: this recomputes from the absolute expiry
    // rather than counting down, so returning to the tab shows the right
    // number immediately instead of a stale one that has to catch up.
    return visibleInterval(() => {
      setLeft(Math.max(0, Math.round((new Date(code.expires_at).getTime() - Date.now()) / 1000)))
    }, 1000)
  }, [code.expires_at])

  return (
    // **Rendered into <body>, not where it sits in the tree.**
    //
    // .modal carries backdrop-filter, and backdrop-filter makes an element a
    // containing block for position:fixed descendants. A nested modal's
    // `inset: 0` backdrop therefore resolved against the settings box instead
    // of the viewport: it blurred part of that box and stopped dead, leaving a
    // hard horizontal edge with everything below it sharp and readable.
    createPortal(
    <div class="modal-backdrop">
      {/* No dismiss-on-backdrop, unlike every other modal here. Closing this
          cancels the pairing window, which is right, but a single click outside
          the box did it silently, and looking at the other machine is exactly
          what somebody is doing while pairing. The window died within seconds
          and the far side was told "could not reach that address", which sent
          people chasing a network fault that did not exist. The x still closes
          it, deliberately. */}
      <div class="modal pair-modal" onClick={(e) => e.stopPropagation()}>
        <div class="modal-head">
          <h2>{t.dispatch.pairTitle}</h2>
          <button type="button"
            class="close"
            onClick={() => (left > 0 ? setConfirmClose(true) : onClose())}
            title={t.actions.close}
          >×</button>
        </div>

        {/* Closing invalidates the code, and the other machine is usually
            mid-typing when somebody reaches for the corner of the dialog. So a
            live code asks first; an expired one just closes. */}
        {confirmClose && (
          <div class="pair-confirm">
            <p>{t.dispatch.pairDiscardAsk}</p>
            {/* **The destructive one is red and says what it destroys.**
                This was "Cancel" beside "Close", with Close wearing the primary
                colour: the button that throws the code away looked like the one
                to press, and neither label said which was which. "Close" is
                also the same word as the X in the corner, which does the
                opposite thing here. Now the wording carries the meaning and the
                colour carries the warning, and the safe choice is the one that
                looks safe. */}
            <div class="pair-confirm-row">
              <button type="button" class="ghost-btn" onClick={() => setConfirmClose(false)}>
                {t.dispatch.pairDiscardNo}
              </button>
              <button type="button" class="btn-danger" onClick={onClose}>
                {t.dispatch.pairDiscardYes}
              </button>
            </div>
          </div>
        )}

        {/* The code and the address are the two things that have to reach the
            other machine, so both get a copy button. Forty characters read off
            a screen and retyped is where pairing actually goes wrong. */}
        <div class="pair-copy">
          <p class="pair-code" id={`clip-${slug(code.code)}`}>{code.code}</p>
          <CopyButton value={code.code} />
        </div>

        <dl class="modal-facts">
          <dt>{t.dispatch.pairAddress}</dt>
          <dd class="pair-addr">
            <code id={`clip-${slug(code.listen)}`}>{code.listen}</code>
            <CopyButton value={code.listen} />
          </dd>
        </dl>

        {/* Tabular figures and a reserved width: the number counts down every
            second, and text that reflows as digits drop is distracting on a
            screen somebody is reading a code from. */}
        <p class="modal-note countdown">
          {left > 0
            ? fill(t.dispatch.pairExpires, { time: countdown(left) })
            : t.dispatch.pairExpired}
        </p>
        {/* An expired code used to be a dead end whose own text told the reader
            to close the window and start over. Nothing about that needed doing
            by hand. There is no button while a code is still live because
            closing the window already cancels it, so walking away is how you
            revoke one. */}
        {left > 0
          ? <p class="modal-note">{t.dispatch.pairWaiting}</p>
          : <button type="button" class="btn pair-renew" onClick={onNew}>{t.dispatch.pairNewCode}</button>}
      </div>
    </div>,
    document.body,
  )
  )
}

/** The joining side: type the code from the other machine. */
function EnterCode({ onClose }: { onClose: () => void }) {
  const { t } = useI18n()
  useScrollLock()
  const [addr, setAddr] = useState('')
  const [code, setCode] = useState('')
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState('')

  // Server codes map to sentences that say what to do, not just what failed.
  const explain = (e: unknown): string => {
    if (e instanceof ApiError) {
      switch (e.code) {
        case 'pair_bad_code': return t.dispatch.errBadCode
        case 'pair_wrong_machine': return t.dispatch.errWrongMachine
        case 'pair_malformed_code': return t.dispatch.errMalformed
        case 'pair_version': return t.dispatch.errVersion
        case 'dispatch_off': return t.dispatch.errOff
        case 'pair_not_showing': return t.dispatch.errNotShowing
        // Refused and dropped are opposite faults and used to share one
        // message. Refused means the address is right and nothing is
        // listening; dropped means something is discarding the packets, which
        // is a firewall rather than a wrong address.
        case 'pair_refused': return t.dispatch.errRefused
        case 'pair_refused_vpn': return t.dispatch.errRefusedVPN
        case 'pair_refused_tailscale': return t.dispatch.errRefusedTailscale
        // Checked before the firewall advice: if the address is not on a
        // network this machine is connected to, nothing else is the problem.
        case 'pair_off_subnet': return t.dispatch.errOffSubnet
        case 'pair_dropped': return t.dispatch.errDropped
        case 'pair_dropped_tailscale': return t.dispatch.errDroppedTailscale
        case 'pair_dropped_vpn': return t.dispatch.errDroppedVPN
      }
    }
    return t.dispatch.errUnreachable
  }

  const submit = async (e: Event) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const peer = await joinWithCode(addr.trim(), code.trim(), label.trim())
      setDone(fill(t.dispatch.pairDone, { name: peer.label || fingerprint(peer.peer_id) }))
      setTimeout(onClose, 1500)
    } catch (err) {
      setError(explain(err))
    } finally {
      setBusy(false)
    }
  }

  // **The backdrop does not dismiss this.**
  //
  // Forty characters typed, one click a few pixels outside the dialog, and the
  // lot is gone. The code dialog opposite has ignored the backdrop for a while;
  // this one still discarded a half-entered pairing, which is worse, because
  // the code it was for is spent either way.
  return createPortal(
    <div class="modal-backdrop">
      <div class="modal pair-modal" onClick={(e) => e.stopPropagation()}>
        <div class="modal-head">
          <h2>{t.dispatch.joinTitle}</h2>
          <button type="button" class="close" onClick={onClose} title={t.actions.close}>×</button>
        </div>

        {error && <p class="gate-error">{error}</p>}
        {done && <p class="modal-note"><strong>{done}</strong></p>}

        <form onSubmit={submit}>
          <label class="field">
            <span>{t.dispatch.joinAddress}</span>
            <input
              value={addr}
              placeholder="192.168.1.20:2912"
              onInput={(e) => setAddr((e.target as HTMLInputElement).value)}
              required
            />
          </label>
          <label class="field">
            <span>{t.dispatch.joinCode}</span>
            {/* Not a password field: the operator is copying 40 characters by
                hand and needs to see what they typed. It is a bearer credential
                for five minutes, not a stored secret. */}
            <input
              value={code}
              spellcheck={false}
              autocomplete="off"
              class="code-input"
              placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
              inputMode="text"
              // Grouped as it is typed, with the same folding the server
              // applies, so a pasted code with dashes, without them, or with
              // spaces all end up identical and a rejected character never
              // reaches the far end.
              onInput={(e) => {
                const el = e.target as HTMLInputElement
                const pos = caretAfterFormat(el.value, el.selectionStart ?? el.value.length)
                const formatted = formatJoinCode(el.value)
                // Written to the element before the state update, so the caret
                // can be placed in the same tick. Setting state first would
                // leave the caret to be restored after a render that has
                // already moved it, which is a frame of visible jumping.
                el.value = formatted
                el.setSelectionRange(pos, pos)
                setCode(formatted)
              }}
              required
            />
            {/* Counted down rather than left to the reader. Forty characters
                is too many to check by eye, and the protocol spends the single
                permitted attempt whether the code was right or merely
                mistyped. */}
            {/* Only rendered where the browser will allow a read: the
                clipboard API needs a secure context, so it exists on
                127.0.0.1 and not on http://192.168.x.y, which is exactly where
                pairing happens. A button that cannot work is not offered. */}
            {/* Said out loud, because the field silently rewrites what you
                type: it upper-cases, folds I/L to 1 and O to 0, and inserts
                the dashes. Without a word of warning that reads as the field
                fighting you rather than helping. */}
            <p class="field-hint">{t.dispatch.joinCodeHint}</p>
            <PasteButton onPaste={(txt) => setCode(formatJoinCode(txt))} />
            {code.length > 0 && joinCodeRemaining(code) > 0 && (
              <small class="code-remaining">
                {fill(t.dispatch.codeRemaining, { n: joinCodeRemaining(code) })}
              </small>
            )}
          </label>
          <label class="field">
            <span>{t.dispatch.joinLabel}</span>
            <input
              value={label}
              onInput={(e) => setLabel((e.target as HTMLInputElement).value)}
            />
          </label>
          <button class="btn" type="submit" disabled={busy || joinCodeRemaining(code) !== 0}>
            {busy ? t.dispatch.joinWorking : t.dispatch.joinSubmit}
          </button>
        </form>
      </div>
    </div>,
    document.body,
  )
}
