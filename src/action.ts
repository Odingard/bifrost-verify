import canonicalizeModule from 'canonicalize';
import { compactVerify, importJWK, calculateJwkThumbprint, type JWK } from 'jose';
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

const canonicalize = canonicalizeModule as unknown as (value: unknown) => string;
type JsonObject = Record<string, any>;

export type ActionArtifact = {
  jws: string;
  jws_sha256: string;
  prior_sha256: string | null;
  signer_domain: string | null;
  created_at: string;
};
export type ActionChainExport = {
  format: string;
  request: {
    id: string;
    counterparty_domain: string;
    action: string;
    parameters_sha256: string;
    nonce: string;
    verdict: string | null;
    reason: string | null;
    grant_id: string | null;
  };
  delegation_credential: string | null;
  delegation_status?: string;
  proposal: ActionArtifact | null;
  decision: ActionArtifact | null;
  acceptance: ActionArtifact | null;
  execution: ActionArtifact | null;
  log_bundles: Array<{ kind: string; receipt?: string; keys?: { keys?: JsonObject[] }; log?: JsonObject }>;
};
export type ActionChainReport = {
  integrity: 'valid' | 'invalid';
  authority: 'valid' | 'invalid' | 'unknown';
  authorization: 'permit' | 'deny' | 'unknown';
  execution: 'reported' | 'none' | 'invalid';
  failures: string[];
  details: {
    delegation?: JsonObject;
    decision?: JsonObject;
    receipts: Array<{ kind: string; jws_sha256: string; valid: boolean; failure?: string }>;
  };
};

async function verifyJws(
  jws: string,
  keys: JsonObject[],
  expectedType: string,
  embeddedKey = false,
): Promise<JsonObject> {
  const header = decodeJwsHeader(jws);
  if (header.typ !== expectedType) throw new Error('typ');
  const candidates = embeddedKey && header.jwk ? [header.jwk as JsonObject] : keys;
  for (const jwk of candidates) {
    if (header.kid && jwk.kid && jwk.kid !== header.kid) continue;
    try {
      await compactVerify(jws, await importJWK(jwk as JWK, String(header.alg ?? 'ES256')));
      return decodeJwsPayload(jws);
    } catch {
      continue;
    }
  }
  throw new Error('signature_invalid');
}

/** Offline re-check of delegation narrowing; returns a failure string or null. */
function narrowingFailure(chain: JsonObject[], credential: JsonObject): string | null {
  if (!chain.length) return 'chain_empty';
  if (chain.length > 3) return 'delegation_depth_exceeded';
  if (chain[0]?.parent_id !== null) return 'chain_root_not_root';
  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i]!;
    if (!Array.isArray(entry.actions) || !entry.actions.length) return 'chain_actions_empty';
  }
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1]!;
    const child = chain[i]!;
    if (child.parent_id !== parent.id) return 'chain_link_broken';
    if (!Array.isArray(child.actions) || child.actions.some((a: unknown) => !parent.actions.includes(a)))
      return 'child_actions_broaden_parent';
    for (const [key, limit] of Object.entries(child.limits ?? {})) {
      const parentLimit = (parent.limits as JsonObject | undefined)?.[key];
      if (
        typeof limit !== 'number' || !Number.isFinite(limit) ||
        typeof parentLimit !== 'number' || limit > parentLimit
      )
        return 'child_limits_broaden_parent';
    }
    if (Number(child.expires_at) > Number(parent.expires_at)) return 'child_outlives_parent';
    if (parent.purpose_code != null && child.purpose_code !== parent.purpose_code)
      return 'child_purpose_broaden_parent';
  }
  const leaf = chain.at(-1)!;
  if (
    leaf.id !== credential.delegation_id ||
    leaf.key_thumbprint !== credential.key_thumbprint ||
    Number(credential.exp) > Number(leaf.expires_at) / 1000 ||
    JSON.stringify(leaf.actions) !== JSON.stringify(credential.actions) ||
    JSON.stringify(leaf.limits ?? {}) !== JSON.stringify(credential.limits ?? {})
  )
    return 'leaf_credential_mismatch';
  return null;
}

/** The chain leaf must itself authorize the envelope's action/purpose/limits. */
function leafAuthorizationFailure(leaf: JsonObject, envelope: JsonObject): string | null {
  if (!Array.isArray(leaf.actions) || !leaf.actions.includes(envelope.action_type))
    return 'action_not_in_leaf';
  if (leaf.purpose_code != null && leaf.purpose_code !== envelope.purpose)
    return 'purpose_not_in_leaf';
  const params = envelope.parameters as JsonObject | undefined;
  for (const [key, cap] of Object.entries((leaf.limits as JsonObject) ?? {})) {
    const value = params?.[key];
    if (typeof cap === 'number' && typeof value === 'number' && value > cap)
      return 'params_exceed_leaf_limits';
  }
  return null;
}

export async function verifyActionChain(
  chain: ActionChainExport,
  opts: {
    orgKeys?: Record<string, { keys: JsonObject[] }>;
    status?: Record<string, string>;
  } = {},
): Promise<ActionChainReport> {
  const failures: string[] = [];
  const receiptResults: ActionChainReport['details']['receipts'] = [];
  const names = ['proposal', 'decision', 'acceptance', 'execution'] as const;
  const artifacts = names.map((kind) => ({ kind, artifact: chain[kind] })).filter(
    (item): item is { kind: (typeof names)[number]; artifact: ActionArtifact } => item.artifact !== null,
  );
  const bundles = new Map((chain.log_bundles ?? []).map((item) => [item.kind, item]));
  let integrity: 'valid' | 'invalid' = 'valid';
  let authority: ActionChainReport['authority'] = 'unknown';
  let authorization: ActionChainReport['authorization'] = 'unknown';
  let execution: ActionChainReport['execution'] = 'none';
  let delegation: JsonObject | undefined;
  let decision: JsonObject | undefined;
  let proposal: JsonObject | undefined;
  let prior = '';

  if (chain.format !== 'bifrost-action-chain/1' || !chain.proposal || !chain.decision) {
    integrity = 'invalid';
    failures.push(!chain.proposal ? 'proposal_missing' : 'decision_missing');
  }

  if (chain.delegation_credential) {
    try {
      const unverified = decodeJwsPayload(chain.delegation_credential);
      const domain = String(unverified.org?.domain ?? '');
      const keys = opts.orgKeys?.[domain]?.keys;
      if (!keys) throw new Error('credential_keys_unavailable');
      delegation = await verifyJws(
        chain.delegation_credential,
        keys,
        'bifrost-delegation+jws',
      );
      const nf = Array.isArray(delegation.chain)
        ? narrowingFailure(delegation.chain as JsonObject[], delegation)
        : 'delegation_chain_invalid';
      if (
        delegation.format !== 'bifrost-delegation/1' ||
        typeof delegation.iat !== 'number' ||
        typeof delegation.exp !== 'number' ||
        !Array.isArray(delegation.chain)
      )
        throw new Error('delegation_chain_invalid');
      if (nf) throw new Error(nf);
      authority = 'valid';
    } catch (error) {
      authority = 'invalid';
      failures.push(error instanceof Error ? error.message : 'credential_invalid');
    }
  }

  for (const { kind, artifact } of artifacts) {
    let valid = true;
    let failure: string | undefined;
    const bundle = bundles.get(kind);
    const jws = artifact.jws;
    try {
      if (sha256hex(jws) !== artifact.jws_sha256) throw new Error('sha256_mismatch');
      if (artifact.prior_sha256 !== (prior || null)) throw new Error('prior_link_broken');
      if (!bundle || bundle.receipt !== jws) throw new Error('log_bundle_missing');
      const header = decodeJwsHeader(jws);
      const keys = artifact.signer_domain
        ? opts.orgKeys?.[artifact.signer_domain]?.keys
        : bundle.keys?.keys;
      const expectedType = {
        proposal: 'bifrost-action-proposal+jws',
        decision: 'bifrost-action-decision+jws',
        acceptance: 'bifrost-action-acceptance+jws',
        execution: 'bifrost-action-execution+jws',
      }[kind];
      if (!keys) throw new Error('signer_keys_unavailable');
      const payload = await verifyJws(jws, keys, expectedType, kind === 'proposal');
      if (kind === 'proposal') proposal = payload;
      if (kind === 'decision') decision = payload;
      const log = bundle.log;
      if (!log?.sth || !log.public_jwk || !Array.isArray(log.audit_path)) throw new Error('log_missing');
      const kid = String(header.kid ?? (header.jwk ? await calculateJwkThumbprint(header.jwk as JWK) : ''));
      if (!kid) throw new Error('log_kid_missing');
      const sth = await verifySth(String(log.sth), log.public_jwk as JWKish);
      const leaf = leafHash(logLeafInput('action', kid, artifact.jws_sha256));
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
    } catch (error) {
      valid = false;
      failure = error instanceof Error ? error.message : 'receipt_invalid';
      integrity = 'invalid';
      failures.push(`${kind}:${failure}`);
    }
    receiptResults.push({ kind, jws_sha256: artifact.jws_sha256, valid, ...(failure ? { failure } : {}) });
    prior = artifact.jws_sha256;
  }

  if (proposal && decision) {
    const envelope = proposal;
    const decisionEnvelope = decision.envelope as JsonObject | undefined;
    try {
      const paramsHash = sha256hex(canonicalize(envelope.parameters));
      if (paramsHash !== envelope.parameters_sha256) throw new Error('params_hash_mismatch');
      if (
        envelope.action_type !== chain.request.action ||
        envelope.parameters_sha256 !== chain.request.parameters_sha256 ||
        envelope.nonce !== chain.request.nonce ||
        decision.parameters_sha256 !== paramsHash ||
        decision.prior_sha256 !== chain.proposal!.jws_sha256 ||
        !decisionEnvelope ||
        decisionEnvelope.action_type !== envelope.action_type ||
        decisionEnvelope.parameters_sha256 !== paramsHash ||
        decisionEnvelope.nonce !== envelope.nonce
      )
        throw new Error('decision_envelope_mismatch');
      if (integrity === 'valid') {
        const auth = decision.claims?.authorization;
        authorization = auth?.verdict === 'permit' ? 'permit' : auth?.verdict === 'deny' ? 'deny' : 'unknown';
        if (chain.request.verdict && chain.request.verdict !== authorization) {
          integrity = 'invalid';
          failures.push('verdict_mismatch');
        }
        if (auth?.grant_id !== chain.request.grant_id) failures.push('grant_mismatch');
        if (delegation && Array.isArray(delegation.chain) && delegation.chain.length) {
          const leafFailure = leafAuthorizationFailure(
            delegation.chain.at(-1) as JsonObject,
            envelope,
          );
          if (leafFailure) {
            authority = 'invalid';
            failures.push(leafFailure);
          }
        }
        if (decision.claims?.authority?.delegation_chain?.join(',') !== delegation?.chain?.map((d: JsonObject) => d.id).join(',')) {
          authority = 'invalid';
          failures.push('delegation_chain_mismatch');
        }
        if (delegation && Number(decision.iat) > Number(delegation.exp)) {
          authority = 'invalid';
          failures.push('delegation_expired_at_decision');
        }
        const statusJws = opts.status?.[delegation?.delegation_id] ?? chain.delegation_status;
        if (statusJws && delegation) {
          try {
            const keys = opts.orgKeys?.[delegation.org?.domain]?.keys;
            if (!keys) throw new Error('status_keys_unavailable');
            const status = await verifyJws(statusJws, keys, 'bifrost-delegation-status+jws');
            if (status.delegation_id !== delegation.delegation_id) throw new Error('status_delegation_mismatch');
            if (status.revoked && typeof status.revoked_at === 'number') {
              if (status.revoked_at > Number(decision.iat)) failures.push(`revoked_after:${status.revoked_at}`);
              else {
                authority = 'invalid';
                failures.push('delegation_revoked_at_decision');
              }
            }
          } catch (error) {
            authority = 'invalid';
            failures.push(error instanceof Error ? error.message : 'status_invalid');
          }
        }
      }
    } catch (error) {
      integrity = 'invalid';
      failures.push(error instanceof Error ? error.message : 'chain_invalid');
    }
  }

  if (chain.execution) {
    if (!chain.acceptance || chain.execution.prior_sha256 !== chain.acceptance.jws_sha256) {
      execution = 'invalid';
      integrity = 'invalid';
      failures.push('execution_without_acceptance');
    } else {
      try {
        const payload = decodeJwsPayload(chain.execution.jws);
        if (!['completed', 'failed'].includes(payload.status)) throw new Error('execution_status_invalid');
        execution = 'reported';
      } catch {
        execution = 'invalid';
        integrity = 'invalid';
        failures.push('execution_invalid');
      }
    }
  }

  return {
    integrity,
    authority,
    authorization,
    execution,
    failures,
    details: { ...(delegation ? { delegation } : {}), ...(decision ? { decision } : {}), receipts: receiptResults },
  };
}
