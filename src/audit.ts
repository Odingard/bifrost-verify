import { compactVerify, importJWK, type JWK } from 'jose';
import {
  decodeJwsHeader,
  decodeJwsPayload,
  leafHash,
  logLeafInput,
  sha256hex,
  verifyInclusion,
  verifySth,
  type JWKish,
} from './core.ts';

type JsonObject = Record<string, any>;

/**
 * The audit-acceptance bundle returned by
 * `GET /v1/audits/:id/acceptance` (): the signed acceptance JWS plus
 * its transparency-log inclusion proof against the tenant's receipt keys.
 */
export type AuditAcceptanceBundle = {
  jws: string;
  bundle: {
    format: string;
    receipt: string;
    keys?: { keys?: JsonObject[] };
    log?: JsonObject;
  };
  status?: Record<string, string>;
};

export type AuditAcceptanceReport = {
  signature: 'valid' | 'invalid';
  logged: boolean;
  outcome: 'accepted' | 'exceptions' | 'unknown';
  failures: string[];
  acceptance?: JsonObject;
};

export async function verifyAuditAcceptance(
  input: AuditAcceptanceBundle,
  opts: { keys?: JsonObject[] } = {},
): Promise<AuditAcceptanceReport> {
  const failures: string[] = [];
  let signature: AuditAcceptanceReport['signature'] = 'invalid';
  let logged = false;
  let outcome: AuditAcceptanceReport['outcome'] = 'unknown';
  let acceptance: JsonObject | undefined;

  const jws = input?.jws;
  const bundle = input?.bundle;
  if (!jws || !bundle) {
    return { signature, logged, outcome, failures: ['malformed_bundle'] };
  }

  try {
    const header = decodeJwsHeader(jws);
    if (header.typ !== 'bifrost-audit-acceptance+jws') throw new Error('typ');
    const keys = opts.keys ?? bundle.keys?.keys;
    if (!keys?.length) throw new Error('signer_keys_unavailable');
    for (const jwk of keys) {
      if (header.kid && (jwk as JsonObject).kid && (jwk as JsonObject).kid !== header.kid)
        continue;
      try {
        await compactVerify(jws, await importJWK(jwk as JWK, String(header.alg ?? 'EdDSA')));
        signature = 'valid';
        break;
      } catch {
        continue;
      }
    }
    if (signature !== 'valid') throw new Error('signature_invalid');
    acceptance = decodeJwsPayload(jws);
    outcome = acceptance.outcome === 'accepted' ? 'accepted' : 'exceptions';
  } catch (error) {
    failures.push(error instanceof Error ? error.message : 'signature_invalid');
  }

  try {
    if (bundle.format !== 'bifrost-audit-acceptance-bundle/1' || bundle.receipt !== jws)
      throw new Error('log_bundle_missing');
    const log = bundle.log;
    if (!log?.sth || !log.public_jwk || !Array.isArray(log.audit_path))
      throw new Error('log_missing');
    const header = decodeJwsHeader(jws);
    const kid = String(header.kid ?? '');
    if (!kid) throw new Error('log_kid_missing');
    const sth = await verifySth(String(log.sth), log.public_jwk as JWKish);
    const leaf = leafHash(logLeafInput('audit_acceptance', kid, sha256hex(jws)));
    if (
      !verifyInclusion(
        leaf,
        Number(log.leaf_index),
        Number(log.tree_size),
        (log.audit_path as string[]).map((hex) => Uint8Array.from(Buffer.from(hex, 'hex'))),
        Uint8Array.from(Buffer.from(sth.root_hash, 'hex')),
      )
    )
      throw new Error('log_inclusion_invalid');
    logged = true;
  } catch (error) {
    failures.push(error instanceof Error ? error.message : 'log_invalid');
  }

  return {
    signature,
    logged,
    outcome,
    failures,
    ...(acceptance ? { acceptance } : {}),
  };
}
