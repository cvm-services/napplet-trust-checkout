/**
 * Verify: the client checks a trust-ring proof against the pinned policy.
 *
 * Policy (non-negotiable):
 *  1. The ring must be an exact subset of the pinned trust set (no outside keys).
 *  2. The ring size must be >= MIN_RING_SIZE (4).
 *  3. The LSAG signature must be valid for the order-bound message.
 *  4. The key image must not have been seen before for this order/epoch.
 *  5. The order must not be expired.
 *  6. The trust set must match the pin (setId + contentHash).
 */

import { bytesToHex } from "@noble/hashes/utils.js";
import { verify as lsagVerify } from "./lsag.ts";
import type { OrderContext, TrustProof } from "./prove.ts";
import { orderMessage } from "./prove.ts";
import type { TrustSet, TrustSetPin } from "./trustset.ts";
import { matchesPin, trustSetContentHash } from "./trustset.ts";

export const MIN_RING_SIZE = 4;

export type VerifyResult =
  | { readonly ok: true; readonly anonymitySetSize: number }
  | { readonly ok: false; readonly reason: string };

/**
 * Key-image seen-set, scoped to an order/epoch to prevent cross-order
 * linkability leakage. The scope key is (orderId, pin.setId).
 */
export interface KeyImageSeenSet {
  /** Map from scopeKey -> Set of key-image hex strings. */
  readonly _store: Map<string, Set<string>>;
}

export function createSeenSet(): KeyImageSeenSet {
  return { _store: new Map() };
}

function scopeKey(order: OrderContext): string {
  return `${order.orderId}:${order.pin.setId}`;
}

/**
 * Check and record a key image. Returns false if the key image was already
 * seen for this order/epoch (one-use enforcement).
 */
function checkAndRecordKeyImage(
  seen: KeyImageSeenSet,
  order: OrderContext,
  keyImage: Uint8Array,
): boolean {
  const key = scopeKey(order);
  let set = seen._store.get(key);
  if (!set) {
    set = new Set();
    seen._store.set(key, set);
  }
  const hex = bytesToHex(keyImage);
  if (set.has(hex)) return false; // already seen — duplicate
  set.add(hex);
  return true;
}

/**
 * Verify a trust-ring proof against the full policy.
 *
 * @param proof     The proof from the operator.
 * @param trustSet  The full pinned trust set (operator supplies this; we check
 *                  it matches the pin).
 * @param pin       The pin the client published (the authority).
 * @param seen      Key-image seen-set for one-use enforcement.
 */
export function verifyProof(
  proof: TrustProof,
  trustSet: TrustSet,
  pin: TrustSetPin,
  seen: KeyImageSeenSet,
): VerifyResult {
  // 6. The trust set must match the pin.
  if (!matchesPin(trustSet, pin)) {
    return {
      ok: false,
      reason: `trust set does not match pin (setId or contentHash mismatch)`,
    };
  }

  // Also verify the proof's pin matches the authority pin.
  if (
    proof.pin.setId !== pin.setId ||
    proof.pin.contentHash !== pin.contentHash
  ) {
    return {
      ok: false,
      reason: "proof's pinned set does not match the verifier's pin",
    };
  }

  // 2. Ring size check.
  if (proof.ring.length < MIN_RING_SIZE) {
    return {
      ok: false,
      reason: `ring size ${proof.ring.length} is below minimum ${MIN_RING_SIZE}`,
    };
  }

  // 1. Ring must be an exact subset of the pinned trust set.
  const setKeys = new Set(trustSet.members.map((m) => bytesToHex(m.publicKey)));
  for (const pk of proof.ring) {
    if (!setKeys.has(bytesToHex(pk))) {
      return {
        ok: false,
        reason: "ring contains a key outside the pinned trust set",
      };
    }
  }

  // Verify no duplicate keys in the ring.
  const ringHexes = proof.ring.map((pk) => bytesToHex(pk));
  if (new Set(ringHexes).size !== ringHexes.length) {
    return {
      ok: false,
      reason: "ring contains duplicate keys",
    };
  }

  // 5. Order must not be expired.
  const now = new Date();
  const expiry = new Date(proof.order.expiresAt);
  if (now > expiry) {
    return {
      ok: false,
      reason: `order expired at ${proof.order.expiresAt}`,
    };
  }

  // 3. LSAG signature must be valid for the order-bound message.
  const message = orderMessage(proof.order);
  if (!lsagVerify(message, proof.ring, proof.signature)) {
    return {
      ok: false,
      reason: "LSAG signature verification failed",
    };
  }

  // 4. Key image must not have been seen for this order/epoch.
  if (!checkAndRecordKeyImage(seen, proof.order, proof.signature.keyImage)) {
    return {
      ok: false,
      reason:
        "key image already used for this order — duplicate proof rejected",
    };
  }

  return {
    ok: true,
    anonymitySetSize: proof.ring.length,
  };
}

/**
 * Re-export for callers who want to pre-check a trust set's content hash
 * without going through the full verify flow.
 */
export { trustSetContentHash };
