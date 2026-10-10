// @bifrost/verify/core — the isomorphic heart of the Bifrost verifier.
// Uint8Array only: no node:* imports, so this module runs in a
// browser as well as Node. SHA-256 from @noble/hashes; Ed25519 from
// @noble/curves (WebCrypto has no Ed25519 on Chrome < 137).
// The Node-facing wrappers live in index.ts.
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes, concatBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { JWK } from 'jose';
import canonicalizeModule from 'canonicalize';
import { otsParse, otsVerify, otsConfirmBlock } from './ots.ts';

export type JWKish = JWK;

export const canonicalize = canonicalizeModule as unknown as (value: unknown) => string;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const sha256Bytes = (data: Uint8Array | string) =>
  nobleSha256(typeof data === 'string' ? enc.encode(data) : data);
export const sha256hex = (data: Uint8Array | string) => bytesToHex(sha256Bytes(data));

// --- RFC 6962 §2.1 hashing ------------------------------------------------
export const leafHash = (input: Uint8Array | string) =>
  nobleSha256(
    concatBytes(
      Uint8Array.of(0x00),
      typeof input === 'string' ? enc.encode(input) : input,
    ),
  );
export const innerHash = (l: Uint8Array, r: Uint8Array) =>
  nobleSha256(concatBytes(Uint8Array.of(0x01), l, r));

const largestPow2LessThan = (n: number) => 1 << Math.floor(Math.log2(n - 1));

/** Merkle tree root over leaf-hash bytes (split at largest pow2 < n). */
export function mth(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return nobleSha256(new Uint8Array(0));
  if (leaves.length === 1) return leaves[0];
  const k = largestPow2LessThan(leaves.length);
  return innerHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

/** Bifrost log leaf input: JCS {v:1, kind, kid, receipt_sha256}. */
export const logLeafInput = (kind: 'answer' | 'review', kid: string, receiptSha256: string) =>
  canonicalize({ v: 1, kind, kid, receipt_sha256: receiptSha256 });

// --- RFC 6962 §2.1.1 inclusion proofs --------------------------------------
export function inclusionProof(
  leaves: Uint8Array[],
  index: number,
  treeSize: number,
): Uint8Array[] {
  const path = (leaves: Uint8Array[], m: number): Uint8Array[] => {
    const n = leaves.length;
    if (n === 1) return [];
    const k = largestPow2LessThan(n);
    return m < k
      ? path(leaves.slice(0, k), m).concat([mth(leaves.slice(k))])
      : path(leaves.slice(k), m - k).concat([mth(leaves.slice(0, k))]);
  };
  if (index < 0 || index >= treeSize || treeSize > leaves.length)
    throw new Error('invalid_inclusion_request');
  return path(leaves.slice(0, treeSize), index);
}

const eq = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((v, i) => v === b[i]);

export function verifyInclusion(
  leaf: Uint8Array,
  index: number,
  treeSize: number,
  auditPath: Uint8Array[],
  root: Uint8Array,
): boolean {
  let fn = index,
    sn = treeSize - 1,
    r = leaf;
  for (const c of auditPath) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = innerHash(c, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = innerHash(r, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return eq(r, root) && sn === 0;
}

// --- RFC 6962 §2.1.2 consistency proofs ------------------------------------
export function consistencyProof(
  leaves: Uint8Array[],
  first: number,
  second: number,
): Uint8Array[] {
  if (!(first > 0 && first <= second && second <= leaves.length))
    throw new Error('invalid_consistency_request');
  if (first === second) return [];
  const subproof = (d: Uint8Array[], m: number, b: boolean): Uint8Array[] => {
    const n = d.length;
    if (m === n) return b ? [] : [mth(d)];
    const k = largestPow2LessThan(n);
    return m <= k
      ? subproof(d.slice(0, k), m, b).concat([mth(d.slice(k))])
      : subproof(d.slice(k), m - k, false).concat([mth(d.slice(0, k))]);
  };
  return subproof(leaves.slice(0, second), first, true);
}

export function verifyConsistency(
  first: number,
  second: number,
  proof: Uint8Array[],
  root1: Uint8Array,
  root2: Uint8Array,
): boolean {
  if (first < 1 || first > second) return false;
  if (first === second) return proof.length === 0 && eq(root1, root2);
  // RFC 6962 §2.1.2 verification, verbatim algorithm.
  const nodes = [...proof];
  if ((first & (first - 1)) === 0) nodes.unshift(root1); // first is a power of two
  let fn = first - 1,
    sn = second - 1;
  while (fn % 2 === 1) {
    fn >>= 1;
    sn >>= 1;
  }
  if (!nodes.length) return false;
  let fr = nodes[0],
    sr = nodes[0];
  for (let i = 1; i < nodes.length; i++) {
    const c = nodes[i];
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = innerHash(c, fr);
      sr = innerHash(c, sr);
      if (fn % 2 === 0)
        while (fn % 2 === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
    } else {
      sr = innerHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return eq(fr, root1) && eq(sr, root2);
}

// --- Log key / signed tree head ---------------------------------------------
/** log_id = hex SHA-256 of the JCS-serialized public JWK. */
export const logId = (publicJwk: JWK) => sha256hex(canonicalize(publicJwk));
export const sthPayload = (p: {
  log_id: string;
  tree_size: number;
  root_hash: string;
  timestamp: string;
}) => canonicalize(p);

export async function verifySth(
  jws: string,
  publicJwk: JWK,
): Promise<{ log_id: string; tree_size: number; root_hash: string; timestamp: string }> {
  const header = decodeJwsHeader(jws);
  if (header.alg !== 'EdDSA' || header.typ !== 'bifrost-sth+jws')
    throw new Error('invalid_sth_header');
  const text = await verifyEd25519Jws(jws, publicJwk);
  const parsed = JSON.parse(text);
  if (canonicalize(parsed) !== text) throw new Error('uncanonical_sth');
  return parsed;
}

// --- Answer-payload merkle root (citation snapshot commitment) --------------
export function merkleRoot(
  citations: Array<{
    chunk_id: string;
    document_id: string;
    version: number;
    locator: string;
    sha256: string;
  }>,
) {
  let nodes: Uint8Array[] = [...citations]
    .sort((a, b) => (a.chunk_id < b.chunk_id ? -1 : a.chunk_id > b.chunk_id ? 1 : 0))
    .map((c) =>
      leafHash(
        canonicalize({
          chunk_id: c.chunk_id,
          document_id: c.document_id,
          version: c.version,
          locator: c.locator,
          sha256: c.sha256,
        }),
      ),
    );
  if (!nodes.length) throw new Error('empty_snapshot');
  while (nodes.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < nodes.length; i += 2)
      next.push(innerHash(nodes[i], nodes[i + 1] ?? nodes[i]));
    nodes = next;
  }
  return bytesToHex(nodes[0]);
}

// --- Bundle verification -----------------------------------------------------
export type ReceiptBundle = {
  format: string;
  receipt: string;
  issuer_origin?: string;
  keys: {
    keys: Array<JWK & { kid: string; status?: string }>;
    roots?: Array<{ kid: string; public_jwk: JWK; provider?: string; status?: string }>;
    certs?: string[];
  };
  log: {
    log_id: string;
    public_jwk: JWK;
    origin?: string;
    checkpoint_vkey?: string;
    sth: string;
    leaf_index: number;
    tree_size: number;
    audit_path: string[];
    witnessed?: { checkpoint: string; tree_size: number; audit_path: string[] };
    anchors?: Array<{
      tree_size: number;
      checkpoint_note_text: string;
      ots_base64: string;
      status: string;
      audit_path: string[];
    }>;
  };
};

export type BundleReport = {
  authenticity: 'valid' | 'invalid';
  evidence_integrity: 'valid' | 'invalid' | 'not_applicable';
  derivation: string | null;
  logged: boolean;
  domain_bound: boolean | null;
  key_status: string;
  key_custody: 'customer-root' | 'bifrost';
  root_bound: boolean | null;
  witnessed: { count: number; listed: number; quorum_met: boolean } | null;
  anchored: { height: number; confirmed: boolean | null } | null;
 /** : informational — the purpose and NDA agreement bound to the
   * request when the receipt was issued. Null on older receipts. */
  purpose: { code: string; label: string } | null;
  agreement: { nda_id: string; version: number; sha256: string } | null;
  failures: string[];
};

/** Offline bundle verification; every named check lands in failures[] when bad. */
export type VerifyBundleOpts = {
  domainKeys?: Array<JWK & { kid: string }>;
  /** Domain-document roots (from --domain-keys/--fetch-domain) — trusted roots. */
  domainRoots?: Array<{ kid: string; x?: string; public_jwk?: JWK }>;
  /** --root pinned JWKs — trusted roots. */
  pinnedRoots?: Array<JWK & { kid?: string }>;
  /** --witness vkeys (repeatable). */
  witnesses?: string[];
  /** Required verified cosignatures (default 1 when witnesses given). */
  witnessQuorum?: number;
  /** --btc-header confirmations {height:headerHex}. */
  btcHeaders?: Record<number, string>;
  /** --check-bitcoin online fetch of block hash+header. */
  checkBitcoin?: (height: number) => Promise<{ hash: string; header: string } | null>;
};
export async function verifyBundle(
  bundle: ReceiptBundle,
  opts?: VerifyBundleOpts,
): Promise<BundleReport> {
  const failures: string[] = [];
  const report: BundleReport = {
    authenticity: 'invalid',
    evidence_integrity: 'not_applicable',
    derivation: null,
    logged: false,
    domain_bound: null,
    key_status: 'unknown',
    key_custody: 'bifrost',
    root_bound: null,
    witnessed: null,
    anchored: null,
    purpose: null,
    agreement: null,
    failures,
  };
  if (bundle.format !== 'bifrost-receipt-bundle/1') {
    failures.push('format');
    return report;
  }
  const jws = bundle.receipt;
  let header: Record<string, any>,
    payloadText: string,
    payload: Record<string, any>;
  try {
    header = decodeJwsHeader(jws);
  } catch {
    failures.push('authenticity');
    return report;
  }
  const key = bundle.keys?.keys?.find((k) => k.kid === header.kid);
  report.key_status = key?.status ?? 'unknown';
  if (header.alg !== 'EdDSA' || header.typ !== 'bifrost-receipt+jws' || !key) {
    failures.push('authenticity');
    return report;
  }
  try {
    payloadText = await verifyEd25519Jws(jws, key);
    payload = JSON.parse(payloadText);
    if (canonicalize(payload) !== payloadText) throw new Error('uncanonical');
    report.authenticity = 'valid';
  } catch {
    failures.push('authenticity');
    return report;
  }
  report.derivation = payload!.assurance?.derivation ?? null;
  report.purpose = payload!.purpose ?? null;
  report.agreement = payload!.agreement ?? null;
  // Evidence integrity: recompute the citation merkle root and compare with the
  // committed snapshot root. Offline this proves commitment consistency only.
  try {
    const recomputed = merkleRoot(
      payload!.citations.map((c: Record<string, unknown>) => ({
        chunk_id: c.chunk_id,
        document_id: c.document_id,
        version: c.version,
        locator: c.locator,
        sha256: c.chunk_sha256,
      })),
    );
    if (payload!.snapshot?.merkle_root === 'sha256:' + recomputed)
      report.evidence_integrity = 'valid';
    else {
      report.evidence_integrity = 'invalid';
      failures.push('evidence_integrity');
    }
  } catch {
    report.evidence_integrity = 'invalid';
    failures.push('evidence_integrity');
  }
  // Log: recompute leaf, verify inclusion against the STH root, verify the STH.
  try {
    const leaf = leafHash(logLeafInput('answer', String(header.kid), sha256hex(jws)));
    const sth = await verifySth(bundle.log.sth, bundle.log.public_jwk);
    if (logId(bundle.log.public_jwk) !== bundle.log.log_id || sth.log_id !== bundle.log.log_id)
      failures.push('log_id');
    if (
      sth.tree_size !== bundle.log.tree_size ||
      !verifyInclusion(
        leaf,
        bundle.log.leaf_index,
        bundle.log.tree_size,
        bundle.log.audit_path.map((h) => hexToBytes(h)),
        hexToBytes(sth.root_hash),
      )
    )
      failures.push('log_inclusion');
    if (!failures.includes('log_inclusion') && !failures.includes('log_id')) report.logged = true;
  } catch {
    failures.push('sth_signature');
  }
  // Owner-domain binding: only a claim — verified against supplied domain keys.
  if (payload!.issuer) {
    report.domain_bound = false;
    const domain = payload!.issuer.domain;
    const domainKeys = opts?.domainKeys;
    if (domainKeys) {
      if (domainKeys.some((k) => k.kid === header.kid && k.x === key.x))
        report.domain_bound = true;
      else failures.push('domain_binding');
    }
    void domain;
  }
 // : customer-root key custody -----------------------------------
  const custody = payload!.assurance?.key_custody;
  if (custody === 'customer-root') {
    report.key_custody = 'customer-root';
    report.root_bound = false;
    // A cert in the bundle must verify against a root, bind subject kid+x, and
    // cover issued_at; sha256(cert) must equal key_cert_sha256.
    let certOk = false;
    const roots = [
      ...(bundle.keys?.roots?.map((r) => ({ kid: r.kid, jwk: r.public_jwk, trusted: false })) ?? []),
      ...(opts?.domainRoots?.map((r) => ({
        kid: r.kid,
        jwk: (r.public_jwk ?? { kty: 'OKP', crv: 'Ed25519', x: r.x }) as JWK,
        trusted: true,
      })) ?? []),
      ...(opts?.pinnedRoots?.map((r) => ({ kid: r.kid ?? '', jwk: r, trusted: true })) ?? []),
    ];
    for (const certJws of bundle.keys?.certs ?? []) {
      try {
        const ch = decodeJwsHeader(certJws);
        if (ch.alg !== 'EdDSA' || ch.typ !== 'bifrost-key-cert+jws') continue;
        // Try every matching root — an untrusted bundle root must not shadow a
        // pinned/domain root with the same kid.
        for (const root of roots.filter((r) => r.kid === ch.kid)) {
          try {
            const text = await verifyEd25519Jws(certJws, root.jwk);
            const cp = JSON.parse(text);
            if (canonicalize(cp) !== text || cp.format !== 'bifrost-key-cert/1') continue;
            if (cp.subject_kid !== header.kid || cp.subject_jwk?.x !== key.x) continue;
            if (!(new Date(cp.not_before).getTime() <= new Date(payload!.issued_at).getTime()) ||
                new Date(payload!.issued_at).getTime() >= new Date(cp.not_after).getTime())
              continue;
            if (sha256hex(certJws) !== payload!.assurance.key_cert_sha256) continue;
            certOk = true;
            if (root.trusted) {
              report.root_bound = true;
              break;
            }
          } catch {
            continue;
          }
        }
      } catch {
        continue;
      }
    }
    if (!certOk) failures.push('key_cert');
  }
 // : witnessed checkpoints ---------------------------------------
  if (bundle.log?.witnessed) {
    const w = bundle.log.witnessed;
    let verified = 0;
    let listed = 0;
    try {
      // Signed note: body, blank line, signature lines — split at the LAST
      // empty line per signed-note.
      const sep = w.checkpoint.lastIndexOf('\n\n');
      if (sep < 0) throw new Error('malformed');
      const bodyText = w.checkpoint.slice(0, sep) + '\n';
      const sigLines = w.checkpoint.slice(sep + 2).split('\n').filter(Boolean);
      const [origin, sizeStr, rootB64] = bodyText.split('\n').filter(Boolean);
      const size = Number(sizeStr);
      // Verify the log's own signature line against the bundle's vkey.
      const logSig = sigLines.find((l) => l.startsWith(`— ${origin} `));
      if (logSig && origin === bundle.log.origin) {
        const raw = base64urlBytes(logSig.split(' ')[2]);
        const pub = base64urlBytes(String(bundle.log.public_jwk.x));
        const keyid = checkpointKeyId(origin, pub, 0x01);
        if (
          raw.length === 68 &&
          bytesToHex(raw.slice(0, 4)) === bytesToHex(keyid) &&
          (await verifyEd25519Raw(raw.slice(4), enc.encode(bodyText), base64urlBytes(String(bundle.log.public_jwk.x))))
        ) {
          // Inclusion proof for the leaf against the checkpoint root.
          const leaf = leafHash(logLeafInput('answer', String(header.kid), sha256hex(jws)));
          if (
            size === w.tree_size &&
            verifyInclusion(leaf, bundle.log.leaf_index, size, w.audit_path.map(hexToBytes), b64ToBytes(rootB64))
          ) {
            // Cosignatures cover the note BODY only (tlog-cosignature).
            const cosigs = sigLines.filter((l) => l.startsWith('— ') && l !== logSig);
            listed = cosigs.length;
            const witnesses = opts?.witnesses ?? [];
            for (const vkey of witnesses) {
              const wv = parseVkey(vkey);
              for (const line of cosigs) {
                const m = line.match(/^— (\S+) (.+)$/);
                if (!m || m[1] !== wv.name) continue;
                const c = b64ToBytes(m[2]);
                const want = checkpointKeyId(wv.name, wv.pub, 0x04);
                if (c.length !== 76 || bytesToHex(c.slice(0, 4)) !== bytesToHex(want)) continue;
                const msg = concatBytes(
                  enc.encode(`cosignature/v1\ntime ${readU64(c, 4)}\n`),
                  enc.encode(bodyText),
                );
                if (await verifyEd25519Raw(c.slice(12), msg, wv.pub)) {
                  verified++;
                  break;
                }
              }
            }
          }
        }
      }
    } catch {
      /* witnessed block malformed → count stays 0 */
    }
    const witnesses = opts?.witnesses?.length ? opts.witnesses : undefined;
    const quorum = witnesses ? (opts?.witnessQuorum ?? 1) : 1;
    report.witnessed = {
      count: verified,
      listed,
      // Without --witness keys nothing can be counted — report listed only.
      quorum_met: witnesses ? verified >= quorum : false,
    };
    if (witnesses && verified < quorum) failures.push('witness_quorum');
  }
 // : OpenTimestamps anchors --------------------------------------
  for (const a of bundle.log?.anchors ?? []) {
    try {
      const note = a.checkpoint_note_text;
      const detached = otsParse(b64ToBytes(a.ots_base64));
      // The proof's commitment must be SHA-256 of the checkpoint note text.
      if (bytesToHex(detached.digest) !== sha256hex(note)) continue;
      const noteLines = note.split('\n').filter(Boolean);
      const [aOrigin, aSizeStr, aRootB64] = noteLines;
      void aOrigin;
      const leaf = leafHash(logLeafInput('answer', String(header.kid), sha256hex(jws)));
      if (
        !verifyInclusion(
          leaf,
          bundle.log.leaf_index,
          Number(aSizeStr),
          a.audit_path.map(hexToBytes),
          b64ToBytes(aRootB64),
        )
      )
        continue;
      const v = otsVerify(detached);
      if (!v.bitcoin.length) continue;
      const path = v.bitcoin[0];
      report.anchored = { height: path.height, confirmed: null };
      const supplied = opts?.btcHeaders?.[path.height];
      if (supplied) {
        const hash = blockHashFromHeader(supplied);
        const c = otsConfirmBlock(path, hash, supplied);
        report.anchored.confirmed = c.confirmed;
        if (!c.confirmed) failures.push('anchor_confirm');
      } else if (opts?.checkBitcoin) {
        const blk = await opts.checkBitcoin(path.height);
        if (blk) {
          const c = otsConfirmBlock(path, blk.hash, blk.header);
          report.anchored.confirmed = c.confirmed;
          if (!c.confirmed) failures.push('anchor_confirm');
        }
      }
      break;
    } catch {
      continue;
    }
  }
  return report;
}
// helpers ---------------------------------------------------------
const b64ToBytes = (s: string) => base64urlBytes(s);
const readU64 = (b: Uint8Array, off: number) => {
  const dv = new DataView(b.buffer, b.byteOffset + off);
  return Number(dv.getUint32(0, false)) * 0x100000000 + dv.getUint32(4, false);
};
/** Raw Ed25519 verify (noble) — used for checkpoint and cosignature lines. */
async function verifyEd25519Raw(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) {
  try {
    return await ed25519.verify(sig, msg, pub);
  } catch {
    return false;
  }
}
/** C2SP keyid: sha256(name‖0x0A‖type‖pub)[:4]. */
export function checkpointKeyId(name: string, pub: Uint8Array, type: number): Uint8Array {
  return sha256Bytes(concatBytes(enc.encode(name), new Uint8Array([0x0a, type]), pub)).slice(0, 4);
}
/** Parses `name+keyidhex+base64(type‖pub)` vkeys (type 0x01 log, 0x04 witness). */
export function parseVkey(vkey: string): { name: string; pub: Uint8Array; type: number } {
  // name and hex keyid contain no '+'; the base64 tail may.
  const parts = vkey.split('+');
  if (parts.length < 3) throw new Error('invalid_vkey');
  const bytes = b64ToBytes(parts.slice(2).join('+'));
  if (bytes.length !== 33) throw new Error('invalid_vkey');
  return { name: parts[0], type: bytes[0], pub: bytes.slice(1) };
}
/** double-SHA256(header) byte-reversed — the block hash. */
export function blockHashFromHeader(headerHex: string): string {
  const h = hexToBytes(headerHex);
  return bytesToHex(new Uint8Array([...sha256Bytes(sha256Bytes(h))].reverse()));
}

/** Decode a compact JWS payload without verifying it (display only). */
export function decodeJwsPayload(jws: string): Record<string, any> {
  const parts = jws.split('.');
  if (parts.length !== 3) throw new Error('invalid_jws');
  return JSON.parse(dec.decode(base64urlBytes(parts[1])));
}
export function decodeJwsHeader(jws: string): Record<string, any> {
  const parts = jws.split('.');
  if (parts.length !== 3) throw new Error('invalid_jws');
  return JSON.parse(dec.decode(base64urlBytes(parts[0])));
}

/** Verify an Ed25519 compact JWS without WebCrypto. Returns the payload text. */
async function verifyEd25519Jws(jws: string, key: JWK): Promise<string> {
  const parts = jws.split('.');
  if (parts.length !== 3) throw new Error('invalid_jws');
  if (key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.x !== 'string')
    throw new Error('invalid_key');
  const ok = await ed25519.verify(
    base64urlBytes(parts[2]),
    enc.encode(parts[0] + '.' + parts[1]),
    base64urlBytes(key.x),
  );
  if (!ok) throw new Error('bad_signature');
  return dec.decode(base64urlBytes(parts[1]));
}

function base64urlBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// --- Review-packet verification ---------------------------------------------
export type PacketReport = {
  authenticity: 'valid' | 'invalid';
  key_status: string;
  payload: Record<string, any> | null;
  failures: string[];
};

/** Verify a signed review packet JWS against a tenant's public keys. */
export async function verifyPacket(
  jws: string,
  keys: Array<JWK & { kid: string; status?: string }>,
): Promise<PacketReport> {
  const failures: string[] = [];
  const report: PacketReport = {
    authenticity: 'invalid',
    key_status: 'unknown',
    payload: null,
    failures,
  };
  let header: Record<string, any>;
  try {
    header = decodeJwsHeader(jws);
  } catch {
    failures.push('authenticity');
    return report;
  }
  const key = keys.find((k) => k.kid === header.kid);
  report.key_status = key?.status ?? 'unknown';
  if (header.alg !== 'EdDSA' || header.typ !== 'bifrost-review-packet+jws' || !key) {
    failures.push('authenticity');
    return report;
  }
  try {
    const text = await verifyEd25519Jws(jws, key);
    const parsed = JSON.parse(text);
    if (canonicalize(parsed) !== text) throw new Error('uncanonical');
    report.payload = parsed;
    report.authenticity = 'valid';
  } catch {
    failures.push('authenticity');
  }
  return report;
}

// --- Live checks -------------------------------------------------------------
const isLoopback = (u: URL) =>
  u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';

/** Guarded fetch for live checks: https or loopback http, no redirects, 5 s, 1 MiB cap. */
async function guardedFetch(url: string, init: RequestInit = {}, fetchImpl = fetch) {
  const u = new URL(url);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && isLoopback(u)))
    throw new Error('disallowed_origin');
  const res = await fetchImpl(u, {
    ...init,
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error('upstream_' + res.status);
  const reader = res.body?.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 1048576) {
        await reader.cancel();
        throw new Error('response_too_large');
      }
      chunks.push(value);
    }
  }
  const bytes = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    bytes.set(c, off);
    off += c.byteLength;
  }
  return dec.decode(bytes);
}

export type OnlineCheck = { signature?: string; key?: string; evidence?: string; [k: string]: unknown };

/** Live check against the vendor's gateway. item: {kind:'receipt',jws} or {kind:'packet',id}. */
export async function checkOnline(
  origin: string,
  item: { kind: 'receipt'; jws: string } | { kind: 'packet'; id: string },
  fetchImpl = fetch,
): Promise<OnlineCheck> {
  const base = origin.replace(/\/+$/, '');
  if (item.kind === 'receipt') {
    const text = await guardedFetch(
      base + '/v1/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jws: item.jws }),
      },
      fetchImpl,
    );
    return JSON.parse(text);
  }
  const text = await guardedFetch(
    base + '/v1/verify/reviews/' + encodeURIComponent(item.id),
    {},
    fetchImpl,
  );
  return JSON.parse(text);
}

/** Fetch signing keys via the public well-known. With a slug the keys are
 * tenant-scoped; without one the gateway's global receipt-key list is
 * returned (it contains the keys that sign review packets). */
export async function fetchTenantKeys(
  origin: string,
  slug?: string,
  fetchImpl = fetch,
): Promise<Array<JWK & { kid: string; status?: string }>> {
  const base = origin.replace(/\/+$/, '');
  const text = await guardedFetch(
    base +
      '/.well-known/bifrost-keys' +
      (slug ? `?tenant=${encodeURIComponent(slug)}` : ''),
    {},
    fetchImpl,
  );
  return (JSON.parse(text) as { keys: Array<JWK & { kid: string; status?: string }> }).keys;
}

/** Fetch a vendor's public log descriptor ({log_id, kid, public_jwk, ...}). */
export async function fetchLogInfo(
  origin: string,
  fetchImpl = fetch,
): Promise<{ log_id: string; [k: string]: unknown }> {
  const base = origin.replace(/\/+$/, '');
  const text = await guardedFetch(`${base}/.well-known/bifrost-log`, {}, fetchImpl);
  return JSON.parse(text) as { log_id: string };
}

/** Fetch the owner-domain key document at the signed issuer.keys_url (any https URL). */
export async function fetchDomainKeys(
  keysUrl: string,
  fetchImpl = fetch,
): Promise<Array<JWK & { kid: string }>> {
  return (await fetchDomainDoc(keysUrl, fetchImpl)).keys;
}
/** Full domain document — keys plus roots/certs. */
export async function fetchDomainDoc(
  keysUrl: string,
  fetchImpl = fetch,
): Promise<{ keys: Array<JWK & { kid: string }>; roots?: Array<{ kid: string; x?: string; public_jwk?: JWK }>; certs?: string[] }> {
  const text = await guardedFetch(keysUrl, {}, fetchImpl);
  return JSON.parse(text) as any;
}
