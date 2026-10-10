// OpenTimestamps detached-proof support (): parse, serialize,
// merge and verify .ots proofs. Browser-safe: Uint8Array only + @noble/hashes.
// Format per python-opentimestamps core/serialize.py, op.py, timestamp.py,
// notary.py.
import { sha256 } from '@noble/hashes/sha2.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

export const OTS_MAGIC = new Uint8Array([
  0x00, ...Array.from('OpenTimestamps').map((c) => c.charCodeAt(0)), 0x00,
  0x00, ...Array.from('Proof').map((c) => c.charCodeAt(0)), 0x00,
  0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
export const TAG_BITCOIN = '0588960d73d71901';
export const TAG_PENDING = '83dfe30d2ef90c8e';
const OP_SHA1 = 0x02;
const OP_RIPEMD160 = 0x03;
const OP_SHA256 = 0x08;
const OP_KECCAK256 = 0x67;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const FORK = 0xff;
const ATTEST = 0x00;
const MAX_MSG = 4096;
const MAX_DEPTH = 256;

export type OtsAttestation = { tag: string; payload: Uint8Array };
export type OtsNode = {
  atts: OtsAttestation[];
  edges: { op: number; arg?: Uint8Array; next?: OtsNode }[];
};

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => new Uint8Array(s.match(/../g)!.map((h) => parseInt(h, 16)));

class Reader {
  pos = 0;
  constructor(readonly buf: Uint8Array) {}
  get eof() {
    return this.pos >= this.buf.length;
  }
  byte() {
    if (this.pos >= this.buf.length) throw new Error('ots_malformed');
    return this.buf[this.pos++];
  }
  peek() {
    return this.buf[this.pos];
  }
  take(n: number) {
    if (this.pos + n > this.buf.length) throw new Error('ots_malformed');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  varuint() {
    let v = 0,
      s = 0;
    for (;;) {
      const b = this.byte();
      v |= (b & 0x7f) << s;
      s += 7;
      if (!(b & 0x80)) return v;
      if (s > 35) throw new Error('ots_malformed');
    }
  }
  varbytes(cap = MAX_MSG) {
    const n = this.varuint();
    if (n > cap) throw new Error('ots_malformed');
    return this.take(n);
  }
}
const encVaruint = (v: number) => {
  const out: number[] = [];
  do {
    let b = v % 128;
    v = Math.floor(v / 128);
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return new Uint8Array(out);
};
const encVarbytes = (b: Uint8Array) => concat([encVaruint(b.length), b]);
export const concat = (parts: Uint8Array[]) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

function parseAttestation(r: Reader): OtsAttestation {
  const tag = hex(r.take(8));
  return { tag, payload: r.varbytes() };
}
function serAttestation(a: OtsAttestation): Uint8Array {
  return concat([new Uint8Array([ATTEST]), unhex(a.tag), encVarbytes(a.payload)]);
}
// A timestamp serializes as: `0xff`-prefixed entries, then one final
// unprefixed entry (an attestation or an op+child). python-ots style.
function parseEntry(r: Reader, node: OtsNode, depth: number) {
  const tag = r.byte();
  if (tag === ATTEST) {
    node.atts.push(parseAttestation(r));
    return;
  }
  let op: { tag: number; arg?: Uint8Array };
  if (tag === OP_APPEND || tag === OP_PREPEND) op = { tag, arg: r.varbytes() };
  else if (tag === OP_SHA256 || tag === OP_SHA1 || tag === OP_RIPEMD160 || tag === OP_KECCAK256)
    op = { tag };
  else throw new Error('ots_malformed');
  node.edges.push({ op: op.tag, arg: op.arg, next: parseNode(r, depth + 1) });
}
function parseNode(r: Reader, depth: number): OtsNode {
  if (depth > MAX_DEPTH || r.eof) throw new Error('ots_malformed');
  const node: OtsNode = { atts: [], edges: [] };
  for (;;) {
    const tag = r.byte();
    if (tag === FORK) {
      if (r.eof) throw new Error('ots_malformed');
      parseEntry(r, node, depth);
      continue;
    }
    r.pos--;
    parseEntry(r, node, depth);
    return node;
  }
}
function serEntry(e: OtsAttestation | OtsNode['edges'][number]): { att?: Uint8Array; op?: Uint8Array } {
  if ('tag' in e) return { att: serAttestation(e) };
  const parts: Uint8Array[] = [];
  if (e.op === OP_APPEND || e.op === OP_PREPEND) parts.push(new Uint8Array([e.op]), encVarbytes(e.arg!));
  else parts.push(new Uint8Array([e.op]));
  parts.push(serNode(e.next!));
  return { op: concat(parts) };
}
function serNode(n: OtsNode): Uint8Array {
  const entries = [...n.atts.map(serAttestation), ...n.edges.map((e) => serEntry(e).op!)];
  if (!entries.length) throw new Error('ots_malformed');
  const parts: Uint8Array[] = [];
  for (let i = 0; i < entries.length - 1; i++) parts.push(new Uint8Array([FORK]), entries[i]);
  parts.push(entries[entries.length - 1]);
  return concat(parts);
}

export type DetachedOts = { digest: Uint8Array; node: OtsNode };

export function otsParse(bytes: Uint8Array): DetachedOts {
  if (bytes.length < OTS_MAGIC.length + 33) throw new Error('ots_malformed');
  const r = new Reader(bytes);
  for (const m of OTS_MAGIC) if (r.byte() !== m) throw new Error('ots_malformed');
  if (r.byte() !== 0x01) throw new Error('ots_malformed'); // major version
  if (r.byte() !== OP_SHA256) throw new Error('ots_malformed'); // file hash op
  const digest = r.take(32);
  const node = parseNode(r, 0);
  if (!r.eof) throw new Error('ots_malformed');
  return { digest, node };
}
/** Parses a bare timestamp tree (calendar /digest and /timestamp responses). */
export function otsParseTimestamp(bytes: Uint8Array): OtsNode {
  const r = new Reader(bytes);
  const node = parseNode(r, 0);
  if (!r.eof) throw new Error('ots_malformed');
  return node;
}
export function otsSerialize(d: DetachedOts): Uint8Array {
  return concat([OTS_MAGIC, new Uint8Array([0x01, OP_SHA256]), d.digest, serNode(d.node)]);
}

/** Merge b into a: union attestations and edges (recursive, keyed by op+arg). */
export function otsMerge(a: DetachedOts, b: DetachedOts): DetachedOts {
  if (hex(a.digest) !== hex(b.digest)) throw new Error('ots_digest_mismatch');
  const edgeKey = (e: OtsNode['edges'][number]) => `${e.op}:${e.arg ? hex(e.arg) : ''}`;
  const mergeNode = (x: OtsNode, y: OtsNode, depth: number): OtsNode => {
    if (depth > MAX_DEPTH) return x;
    for (const at of y.atts)
      if (!x.atts.some((a2) => a2.tag === at.tag && hex(a2.payload) === hex(at.payload)))
        x.atts.push(at);
    for (const e of y.edges) {
      const match = x.edges.find((e2) => edgeKey(e2) === edgeKey(e));
      if (!match) x.edges.push(e);
      else if (e.next && match.next) mergeNode(match.next, e.next, depth + 1);
    }
    return x;
  };
  return { digest: a.digest, node: mergeNode(a.node, b.node, 0) };
}

const applyOp = (op: number, arg: Uint8Array | undefined, msg: Uint8Array): Uint8Array | null => {
  switch (op) {
    case OP_APPEND:
      return concat([msg, arg!]);
    case OP_PREPEND:
      return concat([arg!, msg]);
    case OP_SHA256:
      return sha256(msg);
    case OP_SHA1:
      return sha1(msg);
    case OP_RIPEMD160:
      return ripemd160(msg);
    default:
      return null; // keccak256 + unknown ops → unverifiable branch
  }
};

export type OtsBitcoinPath = { height: number; merkle_root_le_hex: string };
export type OtsPendingUri = { uri: string; commitment: string };
/**
 * Walks every op path from the file digest; collects Bitcoin attestations
 * (with the little-endian merkle-root hex they commit to), pending
 * attestation URIs, and counts unverifiable branches.
 */
export function otsVerify(
  d: DetachedOts,
): { bitcoin: OtsBitcoinPath[]; pending: OtsPendingUri[]; unverifiable: number } {
  const bitcoin: OtsBitcoinPath[] = [];
  const pending: OtsPendingUri[] = [];
  let unverifiable = 0;
  const walk = (msg: Uint8Array, node: OtsNode, depth: number) => {
    if (depth > MAX_DEPTH || msg.length > MAX_MSG) {
      unverifiable++;
      return;
    }
    for (const at of node.atts) {
      if (at.tag === TAG_BITCOIN) {
        const r = new Reader(at.payload);
        const height = r.varuint();
        bitcoin.push({ height, merkle_root_le_hex: hex(msg) });
      } else if (at.tag === TAG_PENDING) {
        if (at.payload.length <= 1000)
          pending.push({ uri: new TextDecoder().decode(at.payload), commitment: hex(msg) });
      }
    }
    for (const e of node.edges) {
      const next = applyOp(e.op, e.arg, msg);
      if (next) walk(next, e.next!, depth + 1);
      else unverifiable++;
    }
  };
  walk(d.digest, d.node, 0);
  return { bitcoin, pending, unverifiable };
}

/**
 * Confirms an anchored path against a real 80-byte Bitcoin block header:
 * double-SHA256(header) byte-reversed must equal the block hash for `height`,
 * and header bytes 36..68 (the merkle root, little-endian) must equal the
 * committed digest. Returns the block time (header bytes 68..72 LE).
 */
export function otsConfirmBlock(
  path: OtsBitcoinPath,
  blockHashHex: string,
  headerHex: string,
): { confirmed: boolean; blockTime?: number } {
  const header = unhex(headerHex);
  if (header.length !== 80) throw new Error('invalid_btc_header');
  const hash = hex(new Uint8Array([...sha256(sha256(header))].reverse()));
  if (hash !== blockHashHex) return { confirmed: false };
  const merkle = hex(header.subarray(36, 68));
  if (merkle !== path.merkle_root_le_hex) return { confirmed: false };
  const dv = new DataView(header.buffer, header.byteOffset);
  return { confirmed: true, blockTime: dv.getUint32(68, true) };
}
