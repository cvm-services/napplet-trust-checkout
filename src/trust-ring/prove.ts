/**
 * Prove: the operator produces a trust-ring proof for a specific order.
 *
 * The signed message binds the order (id, amount, currency, client id, expiry,
 * pinned set id) so a proof cannot be replayed for another order.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { KeyPair, LSAGSignature } from "./lsag.ts";
import { sign } from "./lsag.ts";
import type { TrustSet, TrustSetPin } from "./trustset.ts";

/** The order context that gets bound into the signed message. */
export interface OrderContext {
  readonly orderId: string;
  readonly amount: string;
  readonly currency: string;
  readonly clientId: string;
  /** ISO-8601 expiry — the proof is only valid before this. */
  readonly expiresAt: string;
  /** The pinned trust set the operator claims membership in. */
  readonly pin: TrustSetPin;
}

/**
 * Build the canonical message bytes that the LSAG signature covers.
 * Every field is length-prefixed so concatenation is unambiguous.
 */
export function orderMessage(order: OrderContext): Uint8Array {
  const enc = new TextEncoder();
  const fields = [
    order.orderId,
    order.amount,
    order.currency,
    order.clientId,
    order.expiresAt,
    order.pin.setId,
    order.pin.contentHash,
  ];
  const parts: Uint8Array[] = [enc.encode("TRUST-RING/v1")];
  for (const f of fields) {
    const encoded = enc.encode(f);
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, encoded.length, false);
    parts.push(len, encoded);
  }
  const buf = new Uint8Array(parts.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of parts) {
    buf.set(a, off);
    off += a.length;
  }
  return sha256(buf);
}

export interface TrustProof {
  /** The LSAG signature itself. */
  readonly signature: LSAGSignature;
  /** The ring of public keys used (so the verifier can check subset). */
  readonly ring: Uint8Array[];
  /** The pinned trust set reference. */
  readonly pin: TrustSetPin;
  /** The order context (verifier re-derives the message from this). */
  readonly order: OrderContext;
  /** Anonymity set size = ring.length. Surfaced for honest reporting. */
  readonly anonymitySetSize: number;
}

/**
 * Produce a trust-ring proof.
 *
 * @param trustSet  The full pinned trust set the operator claims membership in.
 * @param signerKey The operator's key pair — their publicKey must be in the set.
 * @param ringIndices  Which members to include in the ring (must include signer,
 *                     must be >= MIN_RING_SIZE, all indices into trustSet.members).
 * @param order     The order to bind the proof to.
 *
 * The signer chooses the ring as a subset of the trust set. The verifier will
 * later confirm: (a) the ring is a subset of the pinned set, (b) ring size
 * >= MIN_RING_SIZE, (c) the proof is valid for the order message.
 */
export function prove(
  trustSet: TrustSet,
  signerKey: KeyPair,
  ringIndices: number[],
  order: OrderContext,
): TrustProof {
  const signerHex = bytesToHex(signerKey.publicKey);

  // Find signer index in the trust set.
  const signerMemberIdx = trustSet.members.findIndex(
    (m) => bytesToHex(m.publicKey) === signerHex,
  );
  if (signerMemberIdx === -1) {
    throw new Error(
      "signer's public key is not in the trust set — cannot prove membership",
    );
  }

  // Validate ring indices.
  for (const idx of ringIndices) {
    if (idx < 0 || idx >= trustSet.members.length) {
      throw new Error(`ring index ${idx} out of range for trust set`);
    }
  }
  if (!ringIndices.includes(signerMemberIdx)) {
    throw new Error("ring must include the signer's own index");
  }

  // Build the ring (public keys in the order the signer chooses).
  // We validated indices above, so we can safely filter here.
  const ring = ringIndices
    .map((i) => trustSet.members[i]?.publicKey)
    .filter((pk): pk is Uint8Array => pk !== undefined);
  const signerPosition = ringIndices.indexOf(signerMemberIdx);

  const message = orderMessage(order);
  const signature = sign(message, ring, signerPosition, signerKey.secretKey);

  return {
    signature,
    ring,
    pin: order.pin,
    order,
    anonymitySetSize: ring.length,
  };
}
