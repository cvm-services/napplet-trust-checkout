/**
 * trust-check — the ring-vetting slice of the checkout, as a NIP-5D napplet.
 *
 * What this shows (and what it deliberately does NOT do):
 *   · The whole trust verdict is local computation — LSAG verify + the ordered
 *     policy — so it needs NO capability at all. The crypto is the part that
 *     ports for free.
 *   · The only NAP it requires is `storage` (it snapshots the pinned-set hash and
 *     the last verdict). `identity` and `theme` are used if the shell has them.
 *   · There is NO network here: no mint quote, no relay, no hand-off. The Cashu
 *     legs are POSTs and the napplet network surface is read-only
 *     (`resource.bytes|bytesMany|cancel`), so they must live in the shell behind a
 *     `cashu` NAP — that is the open design question, not this slice.
 *
 * Set members are generated locally (demo fixtures, no secrets stored): the point
 * is the boundary, not the roster.
 */
import { storage, identity, themeGet, themeOnChanged, cvm } from '@napplet/sdk';
import { generateKeyPair, type KeyPair } from './trust-ring/lsag.ts';
import {
  pinTrustSet, toHex, type TrustSet, type TrustMember, type TrustSetPin,
} from './trust-ring/trustset.ts';
import { createSeenSet, verifyProof, MIN_RING_SIZE, type VerifyResult } from './trust-ring/verify.ts';
import { prove, type OrderContext, type TrustProof } from './trust-ring/prove.ts';

type NappletWindow = Window & { napplet?: Record<string, unknown> };
const napWin = window as NappletWindow;

/** Display-only extras, kept OUT of the member objects (they are not hashed). */
const ROSTER = [
  { label: 'Food Runners Berlin', basis: 'met-in-person', deliveries: 312, rating: 4.9 },
  { label: 'Kreuzberg Couriers', basis: 'vouched', deliveries: 88, rating: 4.7 },
  { label: 'Mitte Bike Messengers', basis: 'met-in-person', deliveries: 205, rating: 4.8 },
  { label: 'Tempelhof Express', basis: 'seed', deliveries: 41, rating: 4.6 },
  { label: 'Neukölln Night Shift', basis: 'vouched', deliveries: 133, rating: 4.8 },
  { label: 'Prenzlauer Pedals', basis: 'met-in-person', deliveries: 77, rating: 4.5 },
  { label: 'Charlottenburg Couriers', basis: 'seed', deliveries: 19, rating: 4.4 },
  { label: 'Wedding Wheels', basis: 'vouched', deliveries: 156, rating: 4.7 },
] as const;

const $ = <T extends HTMLElement>(sel: string): T => document.querySelector(sel) as T;

let keys: KeyPair[] = [];
let set: TrustSet;
let pin: TrustSetPin;
let snapshots = 0;

function buildFixture(): void {
  keys = ROSTER.map(() => generateKeyPair());
  const members: TrustMember[] = ROSTER.map((r, i) => ({
    publicKey: keys[i].publicKey,
    label: r.label,
    basis: r.basis,
  }));
  set = {
    setId: 'pizza-facilitators-berlin',
    description: 'Facilitators the buyer has met, vouched for, or seeded',
    members,
    publishedAt: '2026-09-28T13:20:00Z',
  };
  pin = pinTrustSet(set);
}

/** The order the proof must be bound to — including the SET the buyer pinned. */
function orderContext(p: TrustSetPin = pin): OrderContext {
  return {
    orderId: 'PZ-4471',
    amount: '27900',
    currency: 'sats',
    clientId: 'buyer-demo',
    expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    pin: p,
  };
}

function render(): void {
  const rows = set.members
    .map((m, i) => `<div class="row"><div class="grow">
        <div class="t">${m.label ?? `member ${i}`}</div>
        <div class="s">${ROSTER[i].deliveries} deliveries · ★ ${ROSTER[i].rating} · ${m.basis ?? 'seed'}</div>
      </div><span class="pill ok">in your set</span></div>`)
    .join('');
  $('#set').innerHTML = `
    <div class="h">Your pinned trust set</div>
    <div class="kv"><span>List</span><span>${set.setId}</span></div>
    <div class="kv"><span>Members</span><span>${set.members.length}</span></div>
    <div class="kv"><span>Published</span><span>${set.publishedAt.slice(0, 10)}</span></div>
    <div class="kv"><span>Version hash</span><span class="mono">${pin.contentHash.slice(0, 12)}…</span></div>
    <div class="note">You don't pick one. The order opens to the whole set and the first
      valid proof wins — you never learn which member took it.</div>
    <div class="list">${rows}</div>`;
}

function renderVerdict(res: VerifyResult, proof: TrustProof, selfClaim: string): void {
  const ringHex = proof.ring.map((k) => toHex(k));
  const memberHex = new Set(set.members.map((m) => toHex(m.publicKey)));
  const checks = [
    { label: 'Set matches your pinned version hash', ok: proof.order.pin.contentHash === pin.contentHash },
    { label: `Ring is a subset of your pinned set (${ringHex.length} of ${memberHex.size})`,
      ok: ringHex.length > 0 && ringHex.every((k) => memberHex.has(k)) },
    { label: `Ring size ${ringHex.length} ≥ minimum ${MIN_RING_SIZE}`, ok: ringHex.length >= MIN_RING_SIZE },
    { label: `Proof binds this order — #${proof.order.orderId} · ${Number(proof.order.amount).toLocaleString('en-US')} sats`,
      ok: proof.order.orderId === orderContext().orderId },
    { label: 'Not expired for this delivery window', ok: new Date(proof.order.expiresAt) > new Date() },
    { label: 'Key image fresh — not used for this order before', ok: res.ok },
  ];
  const ok = res.ok;
  const banner = ok
    ? `<div class="banner ok"><b>VERIFIED — a member of your trust set signed this order.</b>
        <div class="s">Identity not revealed — we did not learn <i>which</i> member took it.
        Anonymity set = ${res.ok ? res.anonymitySetSize : proof.ring.length}. Key image
        <span class="mono">${toHex(proof.signature.keyImage).slice(0, 8)}…</span> is one-use per order.</div></div>`
    : `<div class="banner err"><b>Payment blocked — the claimant could not prove membership.</b>
        <div class="mono">reason: ${'reason' in res ? res.reason : 'unknown'}</div>
        <div class="s">No valid proof, no order. Your sats did not move, and the order stays open.</div></div>`;
  $('#verdict').innerHTML = `${banner}
    <ul class="checks">${checks.map((c) =>
      `<li><span class="mk${c.ok ? '' : ' no'}">${c.ok ? '✓' : '✗'}</span><span>${c.label}</span></li>`).join('')}</ul>
    <div class="s">claimant self-claim: <span class="mono">${selfClaim}</span> — ignored, on purpose.</div>`;
  void snapshot(ok ? 'verified' : 'refused');
}

async function snapshot(outcome: string): Promise<void> {
  if (!napWin.napplet || !('storage' in napWin.napplet)) return;
  snapshots += 1;
  await storage.setItem('last-verdict', JSON.stringify({ pin: pin.contentHash, outcome, at: Date.now() }));
  await storage.setItem('snapshots', String(snapshots));
  $('#store').textContent = `storage NAP: wrote ${snapshots} snapshot(s)`;
}

/** An honest claim: a member drawn from the pinned set proves membership. */
function honestClaim(): void {
  const idx = Math.floor(Math.random() * set.members.length);
  const others = set.members.map((_, i) => i).filter((i) => i !== idx).slice(0, MIN_RING_SIZE - 1);
  const proof = prove(set, keys[idx], [idx, ...others], orderContext());
  renderVerdict(verifyProof(proof, set, pin, createSeenSet()), proof, set.members[idx].label ?? '—');
}

/** An impostor: a valid signature over a ring holding a key the buyer never
 *  admitted. The signature verifies; the POLICY is what refuses it. */
function impostorClaim(): void {
  const outsider = generateKeyPair();
  const forged: TrustSet = {
    ...set,
    members: [{ publicKey: outsider.publicKey, label: 'Anon Delivery', basis: 'seed' },
      ...set.members.slice(1)],
  };
  const proof = prove(forged, outsider, [0, 1, 2, 3], orderContext());
  renderVerdict(verifyProof(proof, set, pin, createSeenSet()), proof, 'Anon Delivery');
}

/** A second member claiming an order that is already taken. */
function lateClaim(): void {
  const first = proofForMember(0);
  const claimed = verifyProof(first, set, pin, createSeenSet());
  if (!claimed.ok) { renderVerdict(claimed, first, 'member 0'); return; }
  const late = proofForMember(set.members.length - 1);
  // Same "already claimed" latch the web client enforces: the accepted verdict
  // stands, the late claim is refused without un-verifying the order.
  const accepted = { ok: true as const, anonymitySetSize: claimed.anonymitySetSize };
  renderVerdict(accepted, first, `${set.members[0].label ?? 'member 0'} (accepted)`);
  $('#verdict').insertAdjacentHTML('beforeend',
    `<div class="banner err"><b>Refused — this order is already claimed by a member of your set.</b>
      <div class="mono">reason: this order is already claimed by another member</div>
      <div class="s">A valid proof arrived first (${(set.members[set.members.length - 1].label) ?? 'late member'}
      tried after). Only one facilitator can hold an order.</div></div>`);
  void snapshot('late-claim-refused');
  void late;
}

function proofForMember(idx: number): TrustProof {
  const others = set.members.map((_, i) => i).filter((i) => i !== idx).slice(0, MIN_RING_SIZE - 1);
  return prove(set, keys[idx], [idx, ...others], orderContext());
}

function applyTheme(t: { colors: { background: string; text: string; primary: string } }): void {
  const r = document.documentElement;
  r.style.setProperty('--bg', t.colors.background);
  r.style.setProperty('--fg', t.colors.text);
  r.style.setProperty('--accent', t.colors.primary);
  r.style.backgroundColor = t.colors.background;
  document.body.style.backgroundColor = t.colors.background;
  document.body.style.color = t.colors.text;
}

async function main(): Promise<void> {
  buildFixture();
  render();

  const FALLBACK = { colors: { background: '#0f1115', text: '#e6e8ee', primary: '#6ee7a0' } };
  // Every shell call is feature-detected AND guarded: a partially-implemented or
  // mock runtime must degrade, never crash the boot. (Conformance check
  // `boot/no-boot-error` and `degrade/domain-absence` both depend on this.)
  let themeApplied = false;
  if (napWin.napplet && 'theme' in napWin.napplet) {
    try {
      applyTheme(await themeGet());
      themeOnChanged((t) => { try { applyTheme(t); } catch { /* ignore */ } });
      themeApplied = true;
    } catch { themeApplied = false; }
  }
  if (!themeApplied) applyTheme(FALLBACK);

  const hasStorage = Boolean(napWin.napplet && 'storage' in napWin.napplet);
  let prior: string | null = null;
  if (hasStorage) { try { prior = await storage.getItem('last-verdict'); } catch { prior = null; } }
  $('#store').textContent = !hasStorage
    ? 'storage NAP: absent — running degraded, no crash'
    : prior ? 'storage NAP: found a snapshot from a previous session' : 'storage NAP: nothing stored yet';

  if (napWin.napplet && 'identity' in napWin.napplet) {
    try {
      const pk = await identity.getPublicKey();
      $('#identity').textContent = pk ? `shell identity: ${pk.slice(0, 12)}…` : 'shell identity: none connected';
    } catch {
      $('#identity').textContent = 'identity NAP: present but unreadable in this shell';
    }
  } else {
    $('#identity').textContent = 'identity NAP: absent (optional)';
  }

  // ── NAP-WALLET (proposed domain, feature-detected) ──────────────────────────
  // The checkout needs ONE bit — "can this basket be paid?" — never the balance,
  // never an address, never a signature. The shell compares against a balance it
  // holds privately and answers yes/no. A shell that answers with anything else
  // is a bug we want to SEE, so the response is shape-checked and printed.
  const walletApi = (napWin.napplet && 'wallet' in napWin.napplet)
    ? (napWin.napplet.wallet as {
        canAfford?: (r: { amountSats: number }) => Promise<Record<string, unknown>>;
      })
    : undefined;

  const askAffordability = async (): Promise<void> => {
    const el = $('#afford-res');
    const amountSats = Number(orderContext().amount);
    if (!walletApi || typeof walletApi.canAfford !== 'function') {
      el.textContent = 'wallet NAP: absent — affordability unknown. The verdict does not depend on it.';
      return;
    }
    el.textContent = `asking the shell whether ${amountSats.toLocaleString('en-US')} sats is affordable…`;
    try {
      const r = (await walletApi.canAfford({ amountSats })) ?? {};
      const keys = Object.keys(r);
      const extra = keys.filter((k) => k !== 'affordable' && k !== 'error');
      if (typeof r.error === 'string') {
        el.textContent = `wallet NAP: refused by the shell (${r.error}) — affordability unknown, no balance sent.`;
      } else {
        el.textContent = `wallet NAP: affordable = ${r.affordable === true ? 'yes' : 'no'} `
          + `· response keys [${keys.join(', ')}]`
          + `· methods exposed [${Object.keys(walletApi).join(', ')}]`
          + (extra.length ? ` ⚠ extra fields leaked: ${extra.join(', ')}` : ' · no balance transmitted');
      }
    } catch (e) {
      el.textContent = `wallet NAP: call failed (${e instanceof Error ? e.message : String(e)}) — nothing assumed.`;
    }
    void snapshot('affordability-asked');
  };

  $('#afford').addEventListener('click', () => void askAffordability());
  // Called at boot too, so an automated run captures the envelope without a click.
  void askAffordability();

  // ── NAP-CVM (Sandwich's recommendation) ─────────────────────────────────────
  // Reach the wallet as an MCP tool *through the shell*. The shell owns the
  // transport, the JSON-RPC correlation, policy, and the payment posture; the
  // napplet supplies only a server identity and the operation it wants. No new
  // NAP is needed — and the capability arrives as a named tool, which is
  // something a host can allow-list per name.
  const hasCvm = Boolean(napWin.napplet && 'cvm' in napWin.napplet);

  const askOverCvm = async (): Promise<void> => {
    const el = $('#cvm-res');
    const amountSats = Number(orderContext().amount);
    if (!hasCvm) { el.textContent = 'CVM NAP: absent — no ContextVM bridge in this shell.'; return; }
    const out: string[] = [];
    try {
      const disc = (await cvm.discover({ search: 'wallet', limit: 5 })) as unknown;
      const servers = (Array.isArray(disc) ? disc
        : ((disc as { servers?: unknown[] })?.servers ?? [])) as Array<{
          name?: string; pubkey: string; paymentRequired?: boolean;
        }>;
      out.push(`cvm.discover → ${servers.length} server(s): ` + servers
        .map((s) => `${s.name ?? '(unnamed)'}${s.paymentRequired ? ' · paymentRequired' : ''}`).join(', '));
      const server = servers[0];
      if (!server) { el.textContent = out.join('\n'); return; }

      const listed = (await cvm.listTools(server)) as unknown as { tools?: Array<{ name: string }> };
      out.push(`tools/list → [${(listed?.tools ?? []).map((t) => t.name).join(', ')}]`);

      const r = (await cvm.callTool(server, 'wallet_can_afford', { amountSats })) as unknown as {
        content?: Array<{ text?: string }>;
      };
      out.push(`tools/call wallet_can_afford → "${r?.content?.[0]?.text ?? JSON.stringify(r)}"`);

      // Expected to be refused by the host. If it is ever allowed, say so loudly.
      try {
        const b = (await cvm.callTool(server, 'wallet_balance', {})) as unknown;
        out.push(`tools/call wallet_balance → ⚠ ALLOWED (unexpected): ${JSON.stringify(b).slice(0, 120)}`);
      } catch (e) {
        out.push(`tools/call wallet_balance → refused: ${e instanceof Error ? e.message : String(e)}`);
      }
    } catch (e) {
      out.push(`cvm error: ${e instanceof Error ? e.message : String(e)}`);
    }
    el.textContent = out.join('\n');
    void snapshot('cvm-asked');
  };

  $('#cvm').addEventListener('click', () => void askOverCvm());
  void askOverCvm();   // boot-time, so an automated run captures it without a click

  $('#honest').addEventListener('click', honestClaim);
  $('#impostor').addEventListener('click', impostorClaim);
  $('#late').addEventListener('click', lateClaim);
}

void main().catch((e) => {
  // Last-resort guard: a boot error fails conformance outright.
  const el = document.querySelector('#verdict');
  if (el) el.textContent = `boot error: ${e instanceof Error ? e.message : String(e)}`;
});
