# Changelog

## Unreleased (first pass of the security audit, 2026-11-17; ships in the first tag, 0.0.1)

- A payment for a session already paid or cancelled is `unapplied` (not `rejected`) and the merchant gets a
  `payment.unapplied` webhook in the same transaction (migration 0003).
- Several full nodes per network, which must agree before a payment counts; mainnet requires two on different hosts.
- A payment record is a claim `(digest, nonce)` (migration 0002): anyone who read a `Paid` event could submit its digest
  against another quote of the session first and leave the real payment unrecognised; claims are now independent.
  `GET /v1/sessions/{id}/payments/{digest}` reports the best status among the session's claims of that digest.
- When the API's immediate check and the worker settle the same claim at once, the loser reports the winner's outcome
  instead of `rejected`.
- Verification also compares the `Paid` event's units and subscription reference with the session.
- An RPC outage of the full node no longer rejects a real payment after an hour; only a transaction no node knows is given
  up on.
- `PRICE_MIN_SOURCES` is at least 2 (ADR-0011 §3).
- Every request has a 30-second timeout and at most 64 run at once per process; `unsafe_code` is forbidden.
- `scripts/e2e-testnet.sh` checks the chain identifier, not only the env's name, before it signs.
- A payment that arrives for a cancelled session is recorded as "paid on-chain, but the session was no longer open".

## 0.0.1 — 2026-11-16

- First release: checkout sessions, exact quotes from the median of Kraken, Coinbase and CoinGecko (GBP), the quote message
  shared with the `chain_payments` Move package, payment verification by digest on Sui (gRPC-web), the webhook outbox with
  asymmetric signatures, merchant API keys, the single-writer worker, metrics. Verified end to end on testnet.
