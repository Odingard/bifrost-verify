# @odingard/bifrost-verify

Offline verification for [Bifrost](https://odingard.com) trust artifacts:
signed answer receipts, transparency-log bundles, agent-review packets, and W3C
verifiable credentials.

Bifrost vendors answer buyer questions against their published evidence and
return a signed receipt. This package lets anyone check those artifacts
independently — no Bifrost account, no network calls unless you ask for them.

## What it verifies

- **Receipt bundle JWS** — Ed25519 signature over the receipt payload, checked
  against the issuer's published trust-domain keys (offline via
  `--domain-keys`, or fetched from the issuer's `did:web` document).
- **Evidence integrity** — the citation Merkle root recomputed from each
  cited chunk's SHA-256 matches the signed root. (Checking those hashes against
  the evidence bytes themselves needs the evidence, which the bundle doesn't carry.)
- **Merkle inclusion and consistency** — RFC 6962 inclusion proof tying the
  receipt leaf to the signed tree head, and consistency between tree heads.
- **Signed tree head (STH)** — the log's signed commitment, verified against
  the log key.
- **Witness cosignatures** — optional quorum check over witnessed checkpoints.
- **OpenTimestamps anchors** — optional Bitcoin anchor proofs on checkpoints.
- **Review packets** — the packet JWS minted when an agent review closes.
- **W3C credentials** — Data Integrity `eddsa-jcs-2022` proofs on `did:web`
  issuers (`verifyReceiptCredential`).

## What a valid result proves

A valid report proves **integrity and signer key only**: the artifact is
byte-identical to what the signing key produced, and it was logged under the
claimed tree head. It does **not** prove that the signer had authority to make
the claim, that any review or authorization actually ran, or that the stated
action was ever executed. Trust in the signer's authority is a separate
decision made by the relying party (for example, by recognizing the issuer's
trust domain).

## Getting a receipt

Bundles come from the vendor's Bifrost gateway, not from this package:

- `GET /v1/receipts/<receipt-id>/bundle` — the receipt bundle JSON this
  verifier reads. Requires the reviewer's sign-in on that gateway.
- `GET /v1/receipts/<receipt-id>/credential` — the same receipt exported as a
  W3C verifiable credential (for `bifrost-verify credential`).
- `GET /t/<workspace-slug>/did.json` — the vendor's public `did:web` document
  (the key document `--domain-keys` / `didDocument` consume).

The vendor's web console has a verify page where a reviewer can paste or
upload a bundle or credential and see the same report.

## Quickstart (5 minutes)

```sh
npm install -g @odingard/bifrost-verify

# Synthetic sample shipped with the package — verifies offline, exit 0:
bifrost-verify "$(npm root -g)/@odingard/bifrost-verify/examples/bundle.json"
```

```json
{
  "authenticity": "valid",
  "evidence_integrity": "valid",
  "derivation": "model-entailed",
  "logged": true,
  "key_status": "active",
  "key_custody": "bifrost",
  "failures": []
}
```

(Trimmed — the full report also lists domain binding, witness, anchor,
purpose, and NDA-agreement fields.)

```sh
bifrost-verify "$(npm root -g)/@odingard/bifrost-verify/examples/tampered-bundle.json"
# -> "authenticity": "invalid", "failures": ["authenticity"], exit 1
```

Or verify one of your own: `bifrost-verify <bundle.json> [--fetch-domain]`.

## CLI

```sh
bifrost-verify <bundle.json> [--domain-keys <file>] [--fetch-domain]
    [--root <jwk.json>] [--witness <vkey>]... [--witness-quorum <n>]
    [--btc-header <height>:<hex>] [--check-bitcoin]
bifrost-verify credential <vc.json> [--did-doc <file>] [--fetch-did]
```

Prints the verification report as JSON and exits 0 when there are no
failures, 1 otherwise. By default everything is verified offline;
`--fetch-domain` / `--fetch-did` opt in to fetching the issuer's published
key document.

## API

```ts
import { verifyBundle, verifyPacket, verifyReceiptCredential } from '@odingard/bifrost-verify';

// Receipt bundle (offline — supply the issuer's key document)
const report = await verifyBundle(bundle, { domainKeys: keysDoc });
// or fetch the issuer's keys:
const report2 = await verifyBundle(bundle, { fetchDomain: true });

// Agent-review packet JWS
const packet = await verifyPacket(packetJws, keysDoc.keys);

// W3C verifiable credential (eddsa-jcs-2022, did:web issuer)
const cred = await verifyReceiptCredential(credential, { fetchDid: true });
```

`report.failures` is an empty array when every applicable check passed.
Subpath exports `@odingard/bifrost-verify/core`, `/buyer`, and `/vc` expose the
Merkle/OT/credential primitives for building your own checks.

## Wire formats

The bundle, packet, and credential formats are described in
[SPEC.md](SPEC.md) — the Bifrost exchange spec, v1 draft.

## Requirements

Node.js >= 22. No build step needed — this package ships compiled ESM in
`dist/` with TypeScript declarations.

## License

Apache-2.0 — see [LICENSE](LICENSE).
