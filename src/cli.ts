#!/usr/bin/env node
// bifrost-verify <bundle.json> [--domain-keys <file>] [--fetch-domain]
//   [--root <jwk.json>] [--witness <vkey>]... [--witness-quorum <n>]
//   [--btc-header <height>:<hex>] [--check-bitcoin]
// bifrost-verify credential <vc.json> [--did-doc <file>] [--fetch-did]
// Offline receipt bundle / W3C credential verification; prints the report
// JSON, exit 0 iff no failures.
import { readFile } from 'node:fs/promises';
import { verifyBundle, fetchDomainDoc, type ReceiptBundle } from './index.ts';
import { verifyReceiptCredential } from './vc.ts';
import { verifyActionChain } from './action.ts';
import { verifyAuditAcceptance } from './audit.ts';

const args = process.argv.slice(2);
if (args[0] === 'action') {
  // bifrost-verify action <chain.json> --org-keys <domain>=<file>... [--status <file>] [--fetch-keys]
  const file = args[1];
  if (!file) {
    process.stderr.write(
      'usage: bifrost-verify action <chain.json> --org-keys <domain>=<file>... [--status <status.jws>] [--fetch-keys]\n',
    );
    process.exit(2);
  }
  const chain = JSON.parse(await readFile(file, 'utf8'));
  const orgKeys: Record<string, { keys: Array<Record<string, any>> }> = {};
  const fetchKeys = args.includes('--fetch-keys');
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--org-keys' && args[i + 1]) {
      const [domain, path] = args[++i].split('=');
      orgKeys[domain] = JSON.parse(await readFile(path, 'utf8'));
    }
  }
  if (fetchKeys) {
    const domains = new Set<string>();
    const cred = chain.delegation_credential;
    if (cred)
      try {
        domains.add(JSON.parse(Buffer.from(cred.split('.')[1], 'base64url').toString()).org?.domain);
      } catch {}
    for (const r of chain.receipts ?? []) if (r.signer_domain) domains.add(r.signer_domain);
    for (const d of domains) {
      if (!d || orgKeys[d]) continue;
      const doc = await fetchDomainDoc(`https://${d}/.well-known/bifrost-keys.json`);
      orgKeys[d] = { keys: doc.keys };
    }
  }
  const sIdx = args.indexOf('--status');
  const status: Record<string, string> = {};
  if (chain.delegation_status) {
    try {
      const delegationId = JSON.parse(
        Buffer.from(chain.delegation_status.split('.')[1], 'base64url').toString(),
      ).delegation_id;
      if (delegationId) status[delegationId] = chain.delegation_status;
    } catch {}
  }
  if (sIdx >= 0) {
    const raw = (await readFile(args[sIdx + 1], 'utf8')).trim();
    try {
      const parsed = JSON.parse(raw) as Record<string, string> | string;
      if (typeof parsed === 'string') {
        const delegationId = JSON.parse(
          Buffer.from(parsed.split('.')[1], 'base64url').toString(),
        ).delegation_id;
        if (delegationId) status[delegationId] = parsed;
      } else {
        Object.assign(status, parsed);
      }
    } catch {
      const delegationId = JSON.parse(
        Buffer.from(raw.split('.')[1], 'base64url').toString(),
      ).delegation_id;
      if (delegationId) status[delegationId] = raw;
    }
  }
  const report = await verifyActionChain(chain, {
    orgKeys,
    ...(Object.keys(status).length ? { status } : {}),
  });
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exit(report.failures.length === 0 && report.integrity === 'valid' ? 0 : 1);
}
if (args[0] === 'audit') {
  // bifrost-verify audit <acceptance.json> [--keys <file>]
  const file = args[1];
  if (!file) {
    process.stderr.write('usage: bifrost-verify audit <acceptance.json> [--keys <file>]\n');
    process.exit(2);
  }
  const input = JSON.parse(await readFile(file, 'utf8'));
  const kIdx = args.indexOf('--keys');
  const keys =
    kIdx >= 0
      ? (JSON.parse(await readFile(args[kIdx + 1], 'utf8')) as { keys?: Record<string, any>[] }).keys
      : undefined;
  const report = await verifyAuditAcceptance(input, { keys });
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exit(report.failures.length === 0 ? 0 : 1);
}
if (args[0] === 'credential') {
  const file = args[1];
  if (!file) {
    process.stderr.write('usage: bifrost-verify credential <vc.json> [--did-doc <file>] [--fetch-did]\n');
    process.exit(2);
  }
  const vc = JSON.parse(await readFile(file, 'utf8'));
  let didDocument: Record<string, any> | undefined;
  const ddIdx = args.indexOf('--did-doc');
  const fetchDid = args.includes('--fetch-did');
  if (ddIdx >= 0) didDocument = JSON.parse(await readFile(args[ddIdx + 1], 'utf8'));
  const report = await verifyReceiptCredential(vc, {
    didDocument,
    fetchImpl: !didDocument && fetchDid ? fetch : undefined,
  });
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exit(report.failures.length === 0 ? 0 : 1);
}
const take = (flag: string) => {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) if (args[i] === flag && args[i + 1]) out.push(args[++i]);
  return out;
};
const positional = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--domain-keys');
const file = positional[0];
const dkIdx = args.indexOf('--domain-keys');
const fetchDomain = args.includes('--fetch-domain');
const roots = take('--root');
const witnesses = take('--witness');
const quorumArg = args.indexOf('--witness-quorum');
const btcHeaders = take('--btc-header');
const checkBitcoin = args.includes('--check-bitcoin');
if (!file || (dkIdx >= 0 && !args[dkIdx + 1])) {
  process.stderr.write(
    'usage: bifrost-verify <bundle.json> [--domain-keys <file>] [--fetch-domain] ' +
      '[--root <jwk.json>] [--witness <vkey>]... [--witness-quorum <n>] ' +
      '[--btc-header <height>:<hex>] [--check-bitcoin]\n' +
      '       bifrost-verify credential <vc.json> [--did-doc <file>] [--fetch-did]\n',
  );
  process.exit(2);
}
const bundle = JSON.parse(await readFile(file, 'utf8')) as ReceiptBundle;
let domainKeys, domainRoots;
if (dkIdx >= 0) {
  const doc = JSON.parse(await readFile(args[dkIdx + 1], 'utf8'));
  domainKeys = doc.keys ?? doc;
  domainRoots = doc.roots;
} else if (fetchDomain) {
  let payload: { issuer?: { keys_url?: string; domain?: string } } = {};
  try {
    const text = Buffer.from(bundle.receipt.split('.')[1], 'base64url').toString('utf8');
    payload = JSON.parse(text);
  } catch {}
  const keysUrl =
    payload.issuer?.keys_url ??
    (payload.issuer?.domain ? `https://${payload.issuer.domain}/.well-known/bifrost-keys.json` : null);
  if (!keysUrl) {
    process.stderr.write('receipt carries no issuer claim\n');
    process.exit(2);
  }
  const doc = await fetchDomainDoc(keysUrl);
  domainKeys = doc.keys;
  domainRoots = doc.roots;
}
const pinnedRoots = [];
for (const f of roots) pinnedRoots.push(JSON.parse(await readFile(f, 'utf8')));
const headers: Record<number, string> = {};
for (const h of btcHeaders) {
  const [height, hex] = h.split(':');
  headers[Number(height)] = hex;
}
const report = await verifyBundle(bundle, {
  domainKeys,
  domainRoots,
  pinnedRoots,
  witnesses: witnesses.length ? witnesses : undefined,
  witnessQuorum: quorumArg >= 0 ? Number(args[quorumArg + 1]) : undefined,
  btcHeaders: Object.keys(headers).length ? headers : undefined,
  checkBitcoin: checkBitcoin
    ? async (height: number) => {
        const h = await fetch(`https://blockstream.info/api/block-height/${height}`, {
          redirect: 'error',
          signal: AbortSignal.timeout(10_000),
        });
        if (!h.ok) return null;
        const hash = (await h.text()).trim();
        const r = await fetch(`https://blockstream.info/api/block/${hash}/header`, {
          redirect: 'error',
          signal: AbortSignal.timeout(10_000),
        });
        if (!r.ok) return null;
        return { hash, header: (await r.text()).trim() };
      }
    : undefined,
});
process.stdout.write(JSON.stringify(report, null, 2) + '\n');
process.exit(report.failures.length === 0 ? 0 : 1);
