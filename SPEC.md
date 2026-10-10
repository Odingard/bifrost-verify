# Bifrost exchange — agent review protocol (v1 draft)

Status: Draft, open specification. It describes the exchange as implemented on
`main`; the packet protocol string is still `bifrost-review/1-local-experimental`
and is renamed only when this draft is frozen. Answer receipts are specified in
[bifrost-receipt-v1.md](bifrost-receipt-v1.md); this document covers everything
around them: how a buyer's agent connects, asks, assembles a review, and how
anyone verifies the result without a Bifrost account.

Scope: one vendor workspace (the *responder*) and one buyer agent (the
*requester*). Cross-organization delegation chains and action envelopes are
future work and not part of v1.

## 1. Roles and trust boundaries

- **Responder workspace**: a tenant at `https://<gateway-origin>/t/<slug>`.
  Owns its evidence, disclosure policy, NDA and signing keys.
- **Buyer principal**: a reviewer identity verified by email (one-time code)
  or enterprise SSO. Its organization is derived from the verified email
  domain, never from a request field.
- **Buyer agent**: software acting for the buyer principal through a
  delegation bound to the agent's public key.
- **Verifier**: anyone. Verification needs only public endpoints or an
  offline bundle.

The responder never executes a business operation for the requester. It
discloses evidence-backed answers and signs what it disclosed.

## 2. Transport and authentication

### 2.1 Remote MCP (interactive agents)

- Endpoint: `https://<gateway-origin>/t/<slug>/mcp` (MCP streamable HTTP;
  protocol versions `2025-06-18` and later accepted).
- Discovery: `/.well-known/oauth-protected-resource/t/<slug>/mcp`
  (RFC 9728) names the authorization server.
- Authorization: OAuth 2.1 authorization code + PKCE with dynamic client
  registration. The buyer verifies their email on the consent page.
- Tokens are audience-bound to that MCP endpoint and DPoP-bound (RFC 9449)
  when the workspace requires DPoP (always for the `restricted` tier). A
  request without a valid proof, with a replayed `jti`, or signed by another
  key is rejected.

### 2.2 Agent API (review packets)

Review sessions use the REST agent API. The buyer principal creates a
delegation for the agent key:

```
POST /v1/mcp/delegations   { "jwk": <agent public JWK>, "scopes": [...] }
DELETE /v1/mcp/delegations/:id
```

The returned agent token is bound to the key thumbprint and to the
workspace's agent-policy epoch. Revoking the delegation, disabling agent
access or engaging the kill switch (epoch bump) rejects every later request;
receipts and packets already issued stay verifiable.

## 3. Asking questions (MCP tools)

| Tool | Effect |
|---|---|
| `browse` | Trust page sections visible at the caller's tier: overview, frameworks, controls, subprocessors, documents. |
| `search` | Evidence passages the caller may see. Policy is evaluated before retrieval. |
| `answer_question` | A cited answer with a signed `bifrost-receipt/1`, or a refusal. |
| `get_escalation` | Status of a question routed to the responder's people. |
| `get_document_link` | Short-lived download link for a permitted document. |
| `request_access` | Asks for a higher tier (for example NDA). |

Rules every responder MUST enforce:

1. Authorization (Cedar) runs before any evidence is retrieved, using
   verified claims, tier, grants, purpose and NDA state.
2. No uncited answer is released. An answer is either supported by cited
   evidence or returned as a refusal.
3. Content above the caller's tier is withheld, not summarized. An NDA-tier
   answer requires acceptance of the current NDA version, which the receipt
   records in `agreement`.
4. A question the evidence does not cover becomes an escalation for a
   person, never a generated guess. Once the owner answers it, the
   escalation turns into a normal cited answer.

## 4. Review sessions

```
POST /v1/agent-reviews            Idempotency-Key: <1..100 chars>
  { "questions": [string, ...] (1..500), "required_tier": "public"|"nda"|"restricted", "purpose"?: <code> }
POST /v1/agent-reviews/:id/items  { "ordinal", "receipt_id", "expected_revision" }
POST /v1/agent-reviews/:id/close  { "expected_revision" }
GET  /v1/agent-reviews/:id
GET  /v1/agent-reviews/:id/packet
POST /v1/agent-reviews/:id/follow-ups   { "question" }
```

- Each item attaches an existing answer receipt to a question ordinal.
  `expected_revision` makes concurrent writers fail instead of overwriting.
- Closing signs the packet. A session with every question answered closes
  as `closed`; otherwise it closes as `completed_with_exceptions` and lists
  the unanswered questions in `open_items`.
- Retried writes with the same `Idempotency-Key` return the original result.

## 5. Review packet (`bifrost-review-packet+jws`)

A compact Ed25519 JWS, header `{alg:"EdDSA", kid, typ:"bifrost-review-packet+jws"}`.
The body is exactly the JCS canonicalization of:

```
{
  protocol, packet_id, session_id, tenant_id, reviewer_id,
  delegation_id, key_thumbprint, buyer_org, required_tier,
  nda, grants, status: "closed" | "completed_with_exceptions",
  issued_at,
  receipts: [{ ordinal, receipt_id, jws_sha256, jws }],
  receipt_root:  "sha256:" + SHA-256(JCS(receipts without jws)),
  snapshot_root: "sha256:" + Merkle root of cited evidence chunks | null,
  open_items: [{ ordinal, question, reason }],
  key_custody?: "customer-root", key_cert_sha256?
}
```

`key_custody`/`key_cert_sha256` appear when the workspace signs under a
customer-held root; the key certificate chains the signing key to
that root.

## 6. Acceptance and clearance

- **Acceptance**: recorded when the bound buyer agent retrieves the
  packet (`GET /v1/agent-reviews/:id/packet`). Verification calls, owner and
  admin exports never count. Retrieving again records nothing new.
- **Clearance**: an accepted packet with status `closed` and no
  open items clears the review. One clearance per buyer organization per
  responder in 90 days; later packets in that window are accepted but not
  cleared again. A cleared review produces exactly one usage record for
  metering.
- `completed_with_exceptions` packets are accepted but never cleared.

## 7. Verification

Public, no account:

- `GET /.well-known/bifrost-keys`: workspace signing keys with status
  (`active`, `rotated`, `revoked`).
- `GET /.well-known/bifrost-log`: transparency log head.
- `GET /v1/verify/:id`, `POST /v1/verify`, `POST /v1/verify/bulk`: receipt
  status.
- `GET /v1/verify/reviews/:id`: packet status.
- `GET /v1/receipts/:id/bundle`: offline receipt bundle.
- `GET /v1/receipts/:id/credential`: the receipt as a W3C Verifiable
  Credential (`eddsa-jcs-2022`, issuer `did:web`).

A verifier of a packet MUST:

1. Check the header `alg` is `EdDSA` and `typ` is `bifrost-review-packet+jws`,
   and verify the signature under the published key whose `kid` matches.
2. Check the payload bytes equal their JCS canonicalization.
3. Report the key status. A `revoked` key is reported, not hidden.
4. Recompute `receipt_root` from `receipts` (without `jws`) and check that
   each `jws_sha256` matches its `jws`.
5. Verify each embedded receipt as specified in bifrost-receipt-v1.md.
6. Report `status` and `open_items` as stated. A valid signature on a
   `completed_with_exceptions` packet does not mean the review passed.

Changing any byte of the packet makes step 1 or 2 fail.

The reference verifier is `packages/verify` (`verifyPacket`, `verifyBundle`,
`verifyReceiptCredential`). It also runs in the browser at `/verify`.

## 8. What a valid packet does and does not prove

It proves the named workspace key signed exactly these answers, for this
reviewer and delegation, at this tier and NDA state, and that each answer
cites the evidence chunks it commits to. It does not prove the evidence is
true, and it does not prove any business action happened. Bifrost keeps
integrity, authority, authorization and execution as separate claims.

## 9. Action receipts (L2)

Bifrost extends the exchange with federated action approval receipts.
Each artifact is a compact JWS; `typ` names the artifact:

- `bifrost-delegation+jws` — `bifrost-delegation/1` delegation credential:
  `{format, delegation_id, org:{domain, assurance}, issued_by, keys_url,
  status_url, agent, key_thumbprint, actions[], limits{}, exp, iat, chain[]}`;
  `chain[]` lists every delegation root→leaf as `{id, parent_id, actions,
  limits, purpose_code, expires_at, key_thumbprint}`.
- `bifrost-delegation-status+jws` — `{delegation_id, revoked, revoked_at,
  checked_at}`; `revoked` is chain-aware (any ancestor revocation or the org
  kill switch sets it).
- `bifrost-action-proposal+jws` — the agent's request envelope, signed under
  the chain-leaf DPoP key (`header.jwk` present; its thumbprint equals the
  leaf `key_thumbprint`): `{action_type, parameters, parameters_sha256,
  purpose?, agreement_ref?, requester_org, requester_agent,
  delegation_chain[], nonce, expires_at}` with
  `parameters_sha256 = sha256(JCS(parameters))` and `expires_at ≤ now+300 s`.
- `bifrost-action-decision+jws` — `{typ:"action-decision", request_id,
  envelope, parameters_sha256, prior_sha256, claims:{authority:
  {org_domain, assurance, delegation_chain, valid_at}, authorization:
  {verdict, policy, grant_id?, reason?}, execution:"unconfirmed"},
  tenant_id, issuer_domain, iat, acceptance_url}`. `prior_sha256` is the
  SHA-256 of the proposal JWS; `verdict` is `permit` or `deny`; a deny
  carries a `reason` from the closed set in Bifrost.
- `bifrost-action-acceptance+jws` — `{typ:"action-acceptance", request_id,
  prior_sha256, accepted_at}` where `prior_sha256` is the SHA-256 of the
  decision JWS it accepts.
- `bifrost-action-execution+jws` — `{typ:"action-execution", prior_sha256,
  request_id, status, external_ref?, executed_at}`; its `prior_sha256` is
  the acceptance JWS hash.

Endpoints: `POST /t/:slug/v1/actions` (DPoP proof bound to the chain-leaf
key), `GET /t/:slug/v1/delegations/:id/status`, and
`POST /t/:slug/v1/actions/:id/acceptance` are public and rate-limited. A
chain export (`format: bifrost-action-chain/1`) carries the delegation
credential and ordered receipts with their log bundles; the verifier checks
each artifact's signature against the signing org's published keys, the
`prior_sha256` linkage, the decision envelope against the recorded request,
and — when a live status JWS is supplied — surfaces `revoked_after` for a
chain revoked since the decision. Denied requests still produce a signed
decision receipt; malformed or replayed submissions produce none.

## 10. Audit acceptance (`bifrost-audit-acceptance+jws`)

The vendor's auditor-acceptance flow. An owner/admin opens an
engagement, pins evidence versions into scope and assigns a console user
whose role is `auditor`. The auditor decides each item and signs one
acceptance that closes the engagement.

- Payload: `{typ:"bifrost-audit-acceptance+jws", engagement_id, tenant:
  {slug, did}, framework, period:{start,end}, auditor:{user_id},
  auditor_key_jkt, items:[{document_id, version, content_sha256,
  control_ref, decision, note_sha256}], outcome, iat}`. `outcome` is
  `accepted` when every item's latest decision is `accepted`, otherwise
  `exceptions`. It is signed with the tenant's active receipt key and
  appended to the transparency log as an `audit_acceptance` leaf.
- This is the node attesting that an authenticated auditor (session + DPoP
  key) recorded these decisions — not an independent signature from the
  auditor's own organization (L2 federation is the path for that).
- Endpoints: `POST /v1/admin/audits`, `GET /v1/admin/audits`,
  `GET /v1/admin/audits/:id`, `POST /v1/admin/audits/:id/items`,
  `GET /v1/audits`, `GET /v1/audits/:id`,
  `GET /v1/audits/:id/items/:item/original`,
  `POST /v1/audits/:id/items/:item/decision`,
  `POST /v1/audits/:id/acceptance`, `GET /v1/audits/:id/acceptance`.
  The GET returns `{jws, bundle, status, engagement_status}` where `bundle`
  is `format: bifrost-audit-acceptance-bundle/1` (receipt + keys doc +
  inclusion proof + STH); `status` recomputes each item as
  `current|changed|expired|deleted` like `citationState`.
- `bifrost-verify audit <acceptance.json> [--keys <file>]` verifies the
  signature against the keys doc and the log inclusion proof offline.

## 11. Review-packet bundle (`bifrost-review-packet-bundle/1`)

The buyer-workspace import format. `GET
/v1/agent-reviews/:id/packet/bundle` returns the signed review packet JWS
(`bifrost-review-packet+jws`) plus the tenant's published keys and a
transparency-log inclusion proof for the `review` leaf: `{format,
receipt: <packet jws>, issuer_origin?, keys:{keys[]}, log:{log_id,
leaf_kind:"review", sth, leaf_index, tree_size, audit_path, ...}}`.
`verifyPacketBundle` in `packages/verify` checks the packet signature
against the bundle keys and recomputes the log leaf; `parseInput`/`verifyItem`
accept the format and run the live check against
`GET /v1/verify/reviews/:id`. Buyer-workspace imports require exactly
this format — a plain `bifrost-receipt-bundle/1` is rejected — and
require the live vendor key check to succeed (`vendor_unreachable`, 502,
otherwise). The buyer's recheck hits the same endpoint over time;
a fetch failure is `reachable=false`, never a signature failure.

## 12. Agent interoperability (A2A v1.0.0) and authorization API (AuthZEN 1.0)

Per Bifrost, a Bifrost node is discoverable as an A2A v1.0.0 agent and
exposes an OpenID AuthZEN 1.0 policy-decision endpoint.

- **Agent Card.** `GET /t/:slug/.well-known/agent-card.json` returns a
  tenant's card: `supportedInterfaces` declares one JSONRPC interface at
  `${origin}/t/:slug/a2a` with `protocolVersion: "1.0"`. The tenant's
  `/.well-known/trust.json` carries the same URL as `a2a_agent_card`. The
  standard root `/.well-known/agent-card.json` is served only on
  single-tenant self-hosted nodes (`BIF_A2A_ROOT_SLUG`); unset, it 404s.
- **SendMessage.** `POST /t/:slug/a2a` accepts JSON-RPC `SendMessage` with a
  `SendMessageRequest` (`message.role: "ROLE_USER"`, first `{text}` part is
  the question, an optional `{data}` part `{skill?, purpose?, query?, ...}`
  selects `answer_question`/`search`/`browse`). Authentication reuses the
  tenant's MCP protected resource — same access token, same
  `require_dpop` admission, DPoP `htu` bound to `/t/:slug/a2a`. The result
  is a `ROLE_AGENT` `Message`: a text part (answer or `Refused: <reason>`)
  plus a data part with the MCP tool's structured result (answer,
  citations, signed receipt, refusal) — identical guarantees to MCP
  `tools/call`. Requests must carry `A2A-Version: 1.0`.
- **Errors.** Unknown methods → `-32601`; known-but-unserved operations →
  `UNSUPPORTED_OPERATION` (`-32004`) or `PUSH_NOTIFICATION_NOT_SUPPORTED`
  (`-32003`); `raw`/`url` parts → `CONTENT_TYPE_NOT_SUPPORTED` (`-32005`);
  wrong/absent version → `VERSION_NOT_SUPPORTED` (`-32009`); malformed
  envelopes `-32600`, bad params `-32602`. JSON-RPC envelopes return HTTP
  200; authentication failures return 401 + `WWW-Authenticate`.
- **AuthZEN.** `GET /.well-known/authzen-configuration` lists the PDP and
  both endpoints. `POST /access/v1/evaluation` and `/access/v1/evaluations`
  require the `EvaluateAccess` action (owner/admin, Bifrost). Subjects
  resolve inside the caller's tenant (`agent`/`user`/`reviewer`), the
  resource must be the caller's tenant, unknown inputs deny rather than
  error, and every evaluation is audited. Batch requests accept ≤50 items
  with top-level defaults; `evaluations_semantic` accepts `execute_all`,
  `deny_on_first_deny` and `permit_on_first_permit`. The PDP exposes
  decisions only and is never an enforcement point.
