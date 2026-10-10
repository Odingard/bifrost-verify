# @odingard/bifrost-verify

Offline verification for [Bifrost](https://github.com/Odingard/bifrost-verify) trust artifacts:
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

## CLI

```sh
npm install -g @odingard/bifrost-verify

bifrost-verify <bundle.json> [--domain-keys <file>] [--fetch-domain]
    [--root <jwk.json>] [--witness <vkey>]... [--witness-quorum <n>]
    [--btc-header <height>:<hex>] [--check-bitcoin]
bifrost-verify credential <vc.json> [--did-doc <file>] [--fetch-did]
```

Prints the verification report as JSON and exits 0 when there are no
failures. By default everything is verified offline; `--fetch-domain` /
`--fetch-did` opt in to fetching the issuer's published key document.

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

The bundle, packet, and credential formats are described in the
*Bifrost exchange spec (v1 draft)* (`docs/spec/bifrost-exchange-v1.md`).

## Requirements

Node.js >= 22. No build step needed — this package ships compiled ESM in
`dist/` with TypeScript declarations.

## License

Apache-2.0 — see [LICENSE](LICENSE).
