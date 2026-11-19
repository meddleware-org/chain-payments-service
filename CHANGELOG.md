# Changelog

## 0.0.5 — 2026-11-19

- `chain-payments merchant set-webhook --id <id> (--webhook-url <url> | --clear)` changes or removes a merchant's webhook
  address (validated like `merchant add`; an unknown id fails). Pending deliveries go to the new address, which the worker reads at
  each delivery. `merchant add --key-file` on an existing merchant still changes nothing, but now names a webhook address that differs
  from the one given (FU-0156: a namespace move had left the stored address stale with no command to fix it).

## 0.0.4 — 2026-11-18

- The request limit (64) is per process, as intended: it was per route, because `Router::layer` wraps each route and
  `ConcurrencyLimitLayer` gives each wrap its own semaphore. Both routers use `GlobalConcurrencyLimitLayer` now, with a
  test (FU-0143).

## 0.0.3 — 2026-11-17

- Dates and times use the `time` crate (and sqlx's `time` support) instead of `chrono`, which RUSTSEC-2026-0543 marks
  unmaintained; `chrono` is no longer in the dependency tree and `deny.toml` no longer lists the advisory (FU-0134).
  Timestamps in the API and webhooks are RFC 3339 in UTC with a `Z` suffix.

## 0.0.2 — 2026-11-17

- **Unsubmitted payments are found** (FU-0124). The worker reads each package's `Paid` events through GraphQL
  (`SUI_GRAPHQL_<NETWORK>`, with defaults for testnet and mainnet), from a stored cursor. Every event that pays one of
  its quotes becomes a claim, verified through the full nodes like any other. The metric is
  `chain_payments_payments_found_total`.
- **Merchants are watched** (FU-0122). Every minute the worker reads each merchant object. A pending recipient, a
  recipient other than `methods.json`'s new `recipient`, or a quote key other than this service's stops quoting for that
  merchant. The gauges are `chain_payments_merchant_*`, and the alerts `ChainPaymentsMerchantChanged` and
  `ChainPaymentsMerchantWatchStale`.
- **Unverifiable claims are capped** (FU-0125). A session keeps at most 5 pending claims; one beyond the cap is withdrawn
  with 429.
- **Each process holds only its key** (FU-0126). `serve` needs `QUOTE_KEY_FILE` and `WEBHOOK_PUBLIC_KEY`; `worker` needs
  `WEBHOOK_KEY_FILE` and `QUOTE_PUBLIC_KEY`. A public half that contradicts its key file is refused. The deployment
  mounts each key alone, and merchants are read-only to the service's database role (provisioning's
  `read_only_tables=merchants`), so the merchant Job uses the owner role.
- **Negative quote vectors** (FU-0128) are refused, and CI compares `fixtures/quote-vectors.json` with
  chain-payments-sui's at a pinned commit.
- Migration 0004: `cp.event_cursors`, `cp.merchant_watch`.

## 0.0.1 — 2026-11-17 (first image)

After the first pass of the security audit:

- The testnet package is `0x610cf31f…6af2` (fresh, immutable, with the platform fee). `Paid.platform_fee` is read into
  `Confirmed.platform_fee` and sent to the merchant as `platformFee` in `session.paid` and `payment.unapplied`.
  `scripts/e2e-testnet.sh` passes the `PlatformConfig` and checks the fee (live run 2026-11-17: tx
  `33nefFTR2NG3LcCYzpnRjEsvu6gBTNhgMeDc9EyCqvFa`, fee 35 942 of 17 971 067 MIST).
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

First built 2026-11-16:

- First release: checkout sessions, exact quotes from the median of Kraken, Coinbase and CoinGecko (GBP), the quote message
  shared with the `chain_payments` Move package, payment verification by digest on Sui (gRPC-web), the webhook outbox with
  asymmetric signatures, merchant API keys, the single-writer worker, metrics. Verified end to end on testnet.
