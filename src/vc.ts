// @bifrost/verify/vc — W3C Verifiable Credentials (VC Data Model 2.0,
// Data Integrity eddsa-jcs-2022, did:web issuers) for exported receipts.
// Browser-safe: Uint8Array only, @noble primitives, no node:* imports.
// Vectors: github.com/w3c/vc-di-eddsa TestVectors/eddsa-jcs-2022.
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import canonicalizeModule from 'canonicalize';

const canonicalize = canonicalizeModule as unknown as (v: unknown) => string;
const enc = new TextEncoder();
const dec = new TextDecoder();

// --- base58btc ---------------------------------------------------------------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58MAP = new Map([...B58].map((c, i) => [c, i]));

export function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length || carry; j++) {
      carry += (digits[j] ?? 0) << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
  }
  return '1'.repeat(zeros) + digits.reverse().map((d) => B58[d]).join('');
}

export function base58btcDecode(str: string): Uint8Array {
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;
  const bytes: number[] = [];
  for (let i = zeros; i < str.length; i++) {
    const v = B58MAP.get(str[i]);
    if (v === undefined) throw new Error('invalid_base58');
    let carry = v;
    for (let j = 0; j < bytes.length || carry; j++) {
      carry += (bytes[j] ?? 0) * 58;
      bytes[j] = carry & 0xff;
      carry = carry >> 8;
    }
  }
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes.reverse()]);
}

// --- multikey (Ed25519: 0xed 0x01 || 32-byte pub) ------------------------------
export const multikeyFromEd25519 = (pub: Uint8Array): string => {
  if (pub.length !== 32) throw new Error('invalid_key');
  return 'z' + base58btcEncode(new Uint8Array([0xed, 0x01, ...pub]));
};
export const ed25519FromMultikey = (str: string): Uint8Array => {
  if (!str.startsWith('z')) throw new Error('invalid_multikey');
  const b = base58btcDecode(str.slice(1));
  if (b.length !== 34 || b[0] !== 0xed || b[1] !== 0x01) throw new Error('invalid_multikey');
  return b.slice(2);
};

// --- eddsa-jcs-2022 ------------------------------------------------------------
/** 64-byte signing input: SHA-256(JCS proofConfig) || SHA-256(JCS document). */
export function eddsaJcsHashData(unsecuredDoc: Record<string, any>, proofConfig: Record<string, any>): Uint8Array {
  const doc = { ...unsecuredDoc };
  delete doc.proof;
  return new Uint8Array([
    ...sha256(enc.encode(canonicalize(proofConfig))),
    ...sha256(enc.encode(canonicalize(doc))),
  ]);
}

const jsonEq = (a: unknown, b: unknown) => canonicalize(a) === canonicalize(b);

/** Verify a DataIntegrity eddsa-jcs-2022 proof against a raw Ed25519 key. */
export async function verifyDataIntegrity(doc: Record<string, any>, pub: Uint8Array): Promise<boolean> {
  try {
    const proof = doc.proof;
    if (!proof || proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022')
      return false;
    if (typeof proof.proofValue !== 'string' || !proof.proofValue.startsWith('z')) return false;
    // proof.@context must equal the document's @context (eddsa-jcs-2022 §verify).
    if (!jsonEq(proof['@context'], doc['@context'])) return false;
    const proofConfig = { ...proof };
    delete proofConfig.proofValue;
    const sig = base58btcDecode(proof.proofValue.slice(1));
    return await ed25519.verify(sig, eddsaJcsHashData(doc, proofConfig), pub);
  } catch {
    return false;
  }
}

// --- did:web -------------------------------------------------------------------
/** did:web URL resolution (spec): ':' → '/', %3A → ':', https, /.well-known
 * when there's no path, then /did.json. */
export function didWebUrl(did: string): string {
  if (!did.startsWith('did:web:')) throw new Error('invalid_did');
  const methodId = did.slice('did:web:'.length);
  const path = methodId.replace(/:/g, '/').replace(/%3a/gi, ':');
  const hasPath = methodId.includes(':');
  return `https://${path}${hasPath ? '' : '/.well-known'}/did.json`;
}

/** Build a did:web from a host[:port] and optional path segments (port ':'
 * encoded as %3A). */
export function didWeb(host: string, path: string[] = []): string {
  return 'did:web:' + host.replace(/:/g, '%3A') + (path.length ? ':' + path.join(':') : '');
}

/** Shared DID-document builder (hosted /t/:slug/did.json + vendor did.json). */
export function didDocument(
  did: string,
  keys: Array<{ kid: string; x: string }>,
): Record<string, any> {
  const verificationMethod = keys.map((k) => ({
    id: `${did}#${k.kid}`,
    type: 'Multikey',
    controller: did,
    publicKeyMultibase: multikeyFromEd25519(b64urlBytes(k.x)),
  }));
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod,
    assertionMethod: verificationMethod.map((m) => m.id),
  };
}

// --- Bifrost receipt credentials ------------------------------------------------
/** The credential's inline @context: VC v2 base has no @vocab, so Bifrost
 * terms come from an inline context object (allowed as a later entry). */
export const BIFROST_VC_CONTEXT = [
  'https://www.w3.org/ns/credentials/v2',
  {
    '@vocab': 'https://odingard.com/ns/bifrost/v1#',
    receipt: { '@id': 'https://odingard.com/ns/bifrost/v1#receipt', '@type': '@json' },
  },
];

export type CredentialReport = {
  proof_valid: boolean;
  issuer: string | null;
  verification_method: string | null;
  key_in_did_doc: boolean;
  receipt_matches: boolean;
  jws_valid: boolean;
  failures: string[];
  missing: string[];
  jws?: string;
};

const b64urlBytes = (s: string): Uint8Array => {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
};

const jsonParse = (s: string) => JSON.parse(s) as Record<string, any>;

/** Verify a Bifrost receipt credential against a did:web DID document. */
export async function verifyReceiptCredential(
  vc: Record<string, any>,
  opts: { didDocument?: Record<string, any>; fetchImpl?: typeof fetch } = {},
): Promise<CredentialReport> {
  const r: CredentialReport = {
    proof_valid: false,
    issuer: typeof vc.issuer === 'string' ? vc.issuer : null,
    verification_method: vc.proof?.verificationMethod ?? null,
    key_in_did_doc: false,
    receipt_matches: false,
    jws_valid: false,
    failures: [],
    missing: [],
  };
  const fail = (f: string) => {
    if (!r.failures.includes(f)) r.failures.push(f);
  };
  // Resolve the DID document.
  let doc = opts.didDocument;
  if (!doc) {
    if (!r.issuer || !opts.fetchImpl) {
      r.missing.push('did_resolution');
      return r;
    }
    try {
      const res = await opts.fetchImpl(didWebUrl(r.issuer), { redirect: 'error' });
      if (!res.ok) throw new Error('http_' + res.status);
      doc = jsonParse(await res.text());
    } catch {
      r.missing.push('did_resolution');
      return r;
    }
  }
  if (doc.id !== r.issuer) fail('issuer');
  // The verification method must be an assertionMethod entry controlled by
  // the issuer, and issuer must equal the DID before '#'.
  const vmId = String(r.verification_method ?? '');
  const vm = (doc.verificationMethod ?? []).find((m: any) => m.id === vmId);
  const asserted = (doc.assertionMethod ?? []).some(
    (a: any) => (typeof a === 'string' ? a : a?.id) === vmId,
  );
  const issuerDid = r.issuer ?? '';
  if (!vm || !asserted || vm.controller !== issuerDid || vmId.split('#')[0] !== issuerDid) {
    fail('verification_method');
    return r;
  }
  r.key_in_did_doc = true;
  let pub: Uint8Array;
  try {
    pub = ed25519FromMultikey(String(vm.publicKeyMultibase));
  } catch {
    fail('verification_method');
    return r;
  }
  // The Data Integrity proof verifies under the resolved key.
  r.proof_valid = await verifyDataIntegrity(vc, pub);
  if (!r.proof_valid) fail('proof');
  // evidence[0].jws is the receipt; its payload must equal credentialSubject.
  const jws = vc.evidence?.[0]?.jws;
  if (typeof jws !== 'string') {
    fail('evidence');
    return r;
  }
  r.jws = jws;
  const parts = jws.split('.');
  if (parts.length !== 3) {
    fail('receipt');
    return r;
  }
  let header: Record<string, any>, payload: Record<string, any>, payloadText: string;
  try {
    header = jsonParse(dec.decode(b64urlBytes(parts[0])));
    payloadText = dec.decode(b64urlBytes(parts[1]));
    payload = jsonParse(payloadText);
  } catch {
    fail('receipt');
    return r;
  }
  if (header.typ !== 'bifrost-receipt+jws' || header.alg !== 'EdDSA') fail('receipt_jws');
  // JWS signed with the same key, header kid = verificationMethod fragment.
  try {
    if (await ed25519.verify(b64urlBytes(parts[2]), enc.encode(parts[0] + '.' + parts[1]), pub)) {
      if (`${issuerDid}#${String(header.kid)}` === vmId) r.jws_valid = true;
      else fail('receipt_jws');
    } else fail('receipt_jws');
  } catch {
    fail('receipt_jws');
  }
  // Payload equals credentialSubject.receipt; id + validFrom + created align.
  try {
    if (
      canonicalize(payload) === payloadText &&
      jsonEq(vc.credentialSubject?.receipt, payload) &&
      vc.id === `urn:uuid:${payload.rcpt}` &&
      vc.validFrom === payload.issued_at &&
      vc.proof?.created === payload.issued_at
    ) {
      r.receipt_matches = true;
    } else fail('receipt');
  } catch {
    fail('receipt');
  }
  // Issuer binding: the credential's did:web must match what the verified
  // receipt payload claims — the verified domain, or the hosted
  // did:web:<host>:t:<slug> form whose slug is the payload's tenant.
  if (payload) {
    const domain = payload.issuer?.domain;
    if (domain && !String(domain).startsWith('[')) {
      if (r.issuer !== didWeb(String(domain))) fail('issuer_binding');
    } else {
      const m = (r.issuer ?? '').match(/^did:web:(.+):t:([^:]+)$/);
      if (!m || payload.tenant !== `${m[2]}.local.bifrost`) fail('issuer_binding');
    }
  }
  return r;
}
