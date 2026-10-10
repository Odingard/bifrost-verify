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
