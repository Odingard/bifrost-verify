// @bifrost/verify — offline verification for Bifrost receipts and the global
// transparency log. Node-facing wrapper: Buffer in/Buffer out with the
// historical signatures; the isomorphic logic lives in ./core.ts.
import * as core from './core.ts';
import type { JWK } from 'jose';

export { canonicalize, logLeafInput, sthPayload, logId, verifySth } from './core.ts';
export type { ReceiptBundle, BundleReport, PacketReport } from './core.ts';
export {
  verifyPacket,
  checkOnline,
  fetchTenantKeys,
  fetchDomainKeys,
  decodeJwsPayload,
  decodeJwsHeader,
} from './core.ts';

const bytes = (d: Buffer | string): Uint8Array =>
  typeof d === 'string' ? new TextEncoder().encode(d) : new Uint8Array(d);

export const sha256hex = (data: Buffer | string) => core.sha256hex(bytes(data));

export const leafHash = (input: Buffer | string): Buffer => Buffer.from(core.leafHash(bytes(input)));
export const innerHash = (l: Buffer, r: Buffer): Buffer =>
  Buffer.from(core.innerHash(new Uint8Array(l), new Uint8Array(r)));

export function mth(leaves: Buffer[]): Buffer {
  return Buffer.from(core.mth(leaves.map((l) => new Uint8Array(l))));
}

export function inclusionProof(leaves: Buffer[], index: number, treeSize: number): Buffer[] {
  return core
    .inclusionProof(
      leaves.map((l) => new Uint8Array(l)),
      index,
      treeSize,
    )
    .map((b) => Buffer.from(b));
}

export function verifyInclusion(
  leaf: Buffer,
  index: number,
  treeSize: number,
  auditPath: Buffer[],
  root: Buffer,
): boolean {
  return core.verifyInclusion(
    new Uint8Array(leaf),
    index,
    treeSize,
    auditPath.map((b) => new Uint8Array(b)),
    new Uint8Array(root),
  );
}

export function consistencyProof(leaves: Buffer[], first: number, second: number): Buffer[] {
  return core
    .consistencyProof(
      leaves.map((l) => new Uint8Array(l)),
      first,
      second,
    )
    .map((b) => Buffer.from(b));
}

export function verifyConsistency(
  first: number,
  second: number,
  proof: Buffer[],
  root1: Buffer,
  root2: Buffer,
): boolean {
  return core.verifyConsistency(
    first,
    second,
    proof.map((b) => new Uint8Array(b)),
    new Uint8Array(root1),
    new Uint8Array(root2),
  );
}

export function merkleRoot(
  citations: Array<{
    chunk_id: string;
    document_id: string;
    version: number;
    locator: string;
    sha256: string;
  }>,
) {
  return core.merkleRoot(citations);
}

export async function verifyBundle(
  bundle: core.ReceiptBundle,
  opts?: core.VerifyBundleOpts,
): Promise<core.BundleReport> {
  return core.verifyBundle(bundle, opts);
}
export { fetchDomainDoc } from './core.ts';
export type { VerifyBundleOpts } from './core.ts';
export {
  base58btcEncode,
  base58btcDecode,
  multikeyFromEd25519,
  ed25519FromMultikey,
  eddsaJcsHashData,
  verifyDataIntegrity,
  didWebUrl,
  didWeb,
  didDocument,
  BIFROST_VC_CONTEXT,
  verifyReceiptCredential,
} from './vc.ts';
export type { CredentialReport } from './vc.ts';
