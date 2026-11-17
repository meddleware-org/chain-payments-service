# Security Policy

## Scope

The `chain-payments` binary and image (`serve`, `worker`, `migrate`, `merchant`, `keygen`), from this repository's `main`
and its release tags. Out of scope: the Move package, the SDK and kit (their own policies), full nodes and price sources.

## Security model

1. **Payments are verified on-chain** by digest: effects succeeded and the event of exactly
   `<package>::chain_payments::Paid` (full type, never a suffix) matches the quote — merchant object, session, nonce, coin
   type, amount, units and subscription reference. A submission is a claim that one transaction paid one quote; claims
   are independent, so a wrong claim of a digest cannot block the right one. A session is paid once.
2. **Quotes are bounded**: signed for 120 seconds, single-use nonces enforced on-chain, minimum amounts per coin on-chain.
3. **No quote without agreeing prices**: at least two independent public sources must answer and agree within the
   configured spread.
4. **Secrets**: the quote and webhook keys are separate seed files; API keys are random (192 bits) and stored as SHA-256;
   nothing secret is logged or returned. Database TLS is `verify-full` only.
5. **Exposure**: only the session endpoints are public; the merchant API and metrics listen on a separate port meant to stay
   inside the cluster. CORS is limited to configured origins; responses set no cookie. Each process bounds request time
   and concurrency.
6. **Webhooks** are signed with ed25519 over `<t>.<body>`, re-signed on every attempt, delivered at least once. A merchant
   must check the signature with the key from `/v1/webhook-key`, refuse a timestamp more than five minutes away, treat
   the event id (or the session id) as an idempotency key, and accept only sessions it created.

## Supported versions

The latest release tag and the image digest the platform deploys. Older images are not patched.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository. Please do not open a public issue. Expect an
acknowledgement within a week.

## Disclosure

Coordinated: a fixed image is released and deployed first; the report and the fix are then described in `CHANGELOG.md`
and the audit's re-verification log.
