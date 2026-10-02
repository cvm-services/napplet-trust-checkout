/**
 * Pinned trust set model + hash/pin helpers.
 *
 * A TrustSet is a curated set of public keys the client already trusts (by
 * seed, vouching, or in-person meeting). It is pinned by an event id and
 * content hash so the verifier can prove it is checking against the exact
 * set the client published — not a set the operator substituted.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/** How a member earned their place in the trust set. */
export type TrustBasis = "seed" | "vouched" | "met-in-person";

/** Optional tier — members may carry different trust levels. */
export type TrustTier = "bronze" | "silver" | "gold";

export interface TrustMember {
  /** 33-byte compressed secp256k1 public key. */
  readonly publicKey: Uint8Array;
  /** Optional human label for display only — never used in hashing. */
  readonly label?: string;
  /** How this member was vetted. */
  readonly basis?: TrustBasis;
  /** Trust tier. */
  readonly tier?: TrustTier;
  /** ISO-8601 expiry; after this the member is no longer trusted. */
  readonly expiresAt?: string;
}

export interface TrustSet {
  /** Stable identifier — a Nostr event id, commit hash, or UUID. */
  readonly setId: string;
  /** Human description for display. */
  readonly description: string;
  /** The trusted public keys + metadata. */
  readonly members: readonly TrustMember[];
  /** ISO-8601 timestamp when the set was published. */
  readonly publishedAt: string;
}

/**
 * Content hash of a TrustSet — SHA-256 over the canonical encoding of
 * (setId, sorted member public keys, publishedAt). This is what the verifier
 * pins: the client publishes (setId, contentHash) and the operator must supply
 * a set whose content hash matches.
 */
export function trustSetContentHash(set: TrustSet): string {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [
    enc.encode(set.setId),
    enc.encode(set.publishedAt),
  ];
  // Sort member public keys deterministically (hex sort).
  const sortedHex = set.members.map((m) => bytesToHex(m.publicKey)).sort();
  for (const hex of sortedHex) {
    parts.push(enc.encode(hex));
  }
  const buf = new Uint8Array(parts.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of parts) {
    buf.set(a, off);
    off += a.length;
  }
  return bytesToHex(sha256(buf));
}

/** A pinned reference to a trust set: enough for a verifier to lock down. */
export interface TrustSetPin {
  readonly setId: string;
  readonly contentHash: string;
}

export function pinTrustSet(set: TrustSet): TrustSetPin {
  return {
    setId: set.setId,
    contentHash: trustSetContentHash(set),
  };
}

/**
 * Check that a supplied TrustSet matches a pin.
 * The setId must match and the recomputed content hash must match.
 */
export function matchesPin(set: TrustSet, pin: TrustSetPin): boolean {
  if (set.setId !== pin.setId) return false;
  return trustSetContentHash(set) === pin.contentHash;
}

/** Hex helper for display. */
export function toHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}
