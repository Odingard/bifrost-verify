// @bifrost/verify/buyer — the buyer-side verify pipeline shared by the web
// page and tests. Browser-safe: only imports ./core.ts and web-standard types.
import {
  verifyBundle,
  verifyPacket,
  verifyPacketBundle,
  checkOnline,
  fetchTenantKeys,
  fetchDomainDoc,
  fetchLogInfo,
  decodeJwsHeader,
  decodeJwsPayload,
  type ReceiptBundle,
  type BundleReport,
  type PacketReport,
  type OnlineCheck,
  type JWKish,
} from './core.ts';
import { didWebUrl, verifyReceiptCredential, type CredentialReport } from './vc.ts';

export type ItemKind = 'bundle' | 'receipt' | 'packet' | 'credential';
export type Parsed =
  | { kind: 'bundle'; bundle: ReceiptBundle; jws: string }
  | { kind: 'credential'; credential: Record<string, any>; jws?: string }
  | { kind: 'receipt' | 'packet'; jws: string; id?: string };

export type BuyerResult = {
  kind: ItemKind;
  bundle?: BundleReport;
  credential?: CredentialReport;
  /** The raw bundle document — needed to re-run anchored confirmation. */
  bundleDoc?: ReceiptBundle;
  packet?: PacketReport;
  payload?: Record<string, any> | null;
  issuerOrigin?: string;
  issuerKeysUrl?: string;
  domainBound?: boolean | null;
  live?: OnlineCheck | null;
  liveError?: string;
  /** Who the signatures are anchored to (vendor origin or keys_url host). */
  anchoredTo?: string;
  /** Live log confirmation, e.g. "logged in <origin>'s public log". */
  logLine?: string;
  failures: string[];
  missing: string[];
};

/** Accept a bundle, a bare compact JWS, {jws}, or a packet export {id, jws}. */
export function parseInput(text: string, filename = ''): Parsed | null {
  const trimmed = text.trim();
  try {
    const obj = JSON.parse(trimmed);
    if (obj && typeof obj === 'object') {
      if (
        (obj.format === 'bifrost-receipt-bundle/1' ||
          obj.format === 'bifrost-review-packet-bundle/1') &&
        typeof obj.receipt === 'string'
      )
        return { kind: 'bundle', bundle: obj as ReceiptBundle, jws: obj.receipt };
      if (typeof obj.jws === 'string')
        return jwsParsed(obj.jws, typeof obj.id === 'string' ? obj.id : undefined);
      if (typeof obj.packet === 'string') return jwsParsed(obj.packet);
 // : a W3C credential carrying an eddsa-jcs-2022 proof.
      if (
        Array.isArray(obj.type) &&
        obj.type.includes('VerifiableCredential') &&
        obj.proof?.cryptosuite === 'eddsa-jcs-2022'
      )
        return {
          kind: 'credential',
          credential: obj,
          jws: typeof obj.evidence?.[0]?.jws === 'string' ? obj.evidence[0].jws : undefined,
        };
      return null;
    }
  } catch {
    /* not JSON — maybe a bare JWS */
  }
  void filename;
  return jwsParsed(trimmed);
}
function jwsParsed(jws: string, id?: string): Parsed | null {
  if (!/^[\w-]+\.[\w-]+\.[\w-]+$/.test(jws)) return null;
  let typ = '';
  try {
    typ = String(decodeJwsHeader(jws).typ ?? '');
  } catch {
    return null;
  }
  if (typ === 'bifrost-review-packet+jws') return { kind: 'packet', jws, id };
  if (typ === 'bifrost-receipt+jws') return { kind: 'receipt', jws };
  return null;
}

export const DERIVATION_TEXT: Record<string, string> = {
  'verbatim-excerpt': 'The answer quotes the source documents word for word.',
  'model-entailed':
    'A model wrote the answer and a second check confirmed the evidence supports it.',
  'owner-approved': 'A person at the vendor approved this answer.',
};

const safePayload = (jws: string) => {
  try {
    return decodeJwsPayload(jws);
  } catch {
    return null;
  }
};

export async function verifyItem(
  item: Parsed,
  opts: { live: boolean; origin: string; fetchImpl?: typeof fetch },
): Promise<BuyerResult> {
  const { live, origin, fetchImpl } = opts;
  const f = fetchImpl ?? fetch;
  const result: BuyerResult = { kind: item.kind, failures: [], missing: [] };
  try {
    if (item.kind === 'bundle') {
      const payload = safePayload(item.jws);
      result.payload = payload;
      result.issuerOrigin = item.bundle.issuer_origin;
      result.issuerKeysUrl = payload?.issuer?.keys_url;
      if (item.bundle.format === 'bifrost-review-packet-bundle/1') {
        const report = await verifyPacketBundle(item.bundle);
        result.packet = report;
        result.failures.push(...report.failures);
        result.payload = report.payload;
        result.bundleDoc = item.bundle;
      } else {
      let domainKeys: Array<JWKish & { kid: string }> | undefined;
      let domainRoots;
      if (payload?.issuer?.keys_url && live) {
        try {
          const doc = await fetchDomainDoc(payload.issuer.keys_url, f);
          domainKeys = doc.keys;
          domainRoots = doc.roots;
        } catch {
          result.missing.push('issuer domain keys could not be fetched');
        }
      } else if (payload?.issuer) {
        result.missing.push('issuer domain claim present but not verified');
      }
      result.bundle = await verifyBundle(item.bundle, { domainKeys, domainRoots });
      result.bundleDoc = item.bundle;
      result.domainBound = result.bundle.domain_bound;
      result.failures.push(...result.bundle.failures);
      }
    } else if (item.kind === 'credential') {
      const cred = await verifyReceiptCredential(item.credential, {
        fetchImpl: live ? (f as typeof fetch) : undefined,
      });
      result.credential = cred;
      result.payload = safePayload(cred.jws ?? '');
      result.failures.push(...cred.failures);
      result.missing.push(...cred.missing);
      // The embedded receipt JWS gets the same live check as a bare receipt in
      // the shared block below (checkOnline receipt + anchoredTo).
      if (cred.jws && !cred.jws_valid && !(live && origin))
        result.missing.push('offline signature not checked: key bundle needed');
    } else if (item.kind === 'packet') {
      result.payload = safePayload(item.jws);
      if (live && origin) {
        const keys = await fetchTenantKeys(origin, undefined, f);
        result.packet = await verifyPacket(item.jws, keys);
        result.failures.push(...result.packet.failures);
      } else {
        result.missing.push('signature not checked: vendor keys needed');
      }
    } else {
      // bare receipt JWS: authenticity needs the vendor's live check.
      result.payload = safePayload(item.jws);
      result.missing.push('offline signature not checked: key bundle needed');
    }
    if (live && origin) {
      try {
        if (item.kind === 'packet') {
          const id = item.id ?? result.payload?.packet_id ?? result.payload?.id;
          if (id) result.live = await checkOnline(origin, { kind: 'packet', id }, f);
        } else if (
          item.kind === 'bundle' &&
          item.bundle.format === 'bifrost-review-packet-bundle/1'
        ) {
          const keys = await fetchTenantKeys(origin, undefined, f);
          const livePacket = await verifyPacket(item.jws, keys);
          if (livePacket.authenticity !== 'valid') result.failures.push('signature');
          const id = result.payload?.packet_id;
          if (typeof id === 'string') result.live = await checkOnline(origin, { kind: 'packet', id }, f);
        } else {
          const jws = item.kind === 'credential' ? (result.credential?.jws ?? item.jws) : item.jws;
          if (jws) result.live = await checkOnline(origin, { kind: 'receipt', jws }, f);
        }
      } catch {
        result.liveError = 'vendor check failed';
      }
      // Live trust anchor + public-log id cross-check.
      if (item.kind === 'bundle') {
        if (result.live?.signature === 'invalid') result.failures.push('signature');
        try {
          const info = await fetchLogInfo(origin, f);
          if (info.log_id !== item.bundle.log.log_id) result.failures.push('log_mismatch');
          else if (result.bundle?.logged) result.logLine = `logged in ${origin}'s public log`;
        } catch {
          /* log info unavailable — not a failure on its own */
        }
      }
      if (item.kind === 'receipt' && result.live?.signature === 'invalid')
        result.failures.push('signature');
      if (result.live?.signature === 'valid') result.anchoredTo = origin;
    }
    if (result.domainBound === true && result.issuerKeysUrl) {
      try {
        result.anchoredTo = result.anchoredTo ?? new URL(result.issuerKeysUrl).host;
      } catch {
        result.anchoredTo = result.anchoredTo ?? result.issuerKeysUrl;
      }
    }
  } catch (e) {
    result.missing.push(e instanceof Error ? e.message : 'verification failed');
  }
  return result;
}

export type Verdict = { cls: 'ok' | 'warn' | 'error'; text: string };

export function verdict(r: BuyerResult): Verdict {
  const liveChanged = r.live && r.live.evidence && r.live.evidence !== 'current';
  if (r.failures.length > 0) return { cls: 'error', text: 'Failed — ' + r.failures.join(', ') };
  if (liveChanged)
    return { cls: 'warn', text: 'Verified, but the vendor reports evidence changed.' };
  const authenticity =
    r.kind === 'receipt' ? r.live?.signature : (r.bundle?.authenticity ?? r.packet?.authenticity);
  if (authenticity === 'valid' && r.anchoredTo) return { cls: 'ok', text: 'Verified' };
  if (authenticity === 'valid')
    return {
      cls: 'warn',
      text:
        'Signatures match the keys inside the file, but nothing ties those keys to a ' +
        'vendor yet. Check with the vendor or a verified domain.',
    };
  return { cls: 'warn', text: 'Could not fully verify — see what is missing.' };
}

/** Plain words for the enum values the gateway and core report. */
export const STATUS_TEXT: Record<string, string> = {
  valid: 'valid',
  invalid: 'does not match',
  not_applicable: 'not applicable',
  changed: 'changed',
  deleted: 'deleted',
  current: 'current',
  revoked: 'revoked',
  active: 'valid',
  rotated: 'rotated',
  unknown: 'unknown',
};
export const statusText = (v: string | undefined | null, fallback = 'not checked') =>
  v ? (STATUS_TEXT[v] ?? v) : fallback;
