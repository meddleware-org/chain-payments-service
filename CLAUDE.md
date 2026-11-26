# CLAUDE.md — chain-payments-service

The off-chain side of Chain Payments: merchants create checkout sessions; a buyer's checkout gets an exact, signed quote
in a coin, pays it on-chain (the `chain_payments` Move package, repository `chain-payments-sui`), and submits the digest;
this service verifies the payment and tells the merchant by a signed webhook. Usage: [README.md](README.md).

## Invariants

- **No operator data in this repository.** Hosts, merchant names, recipients and keys belong to the operator's private
  deployment. `examples/methods.json` points at the public testnet package and a throwaway TEST merchant.
- **The quote message is a contract with the Move package** (`crates/core/src/quote.rs`). `fixtures/quote-vectors.json`
  is copied from chain-payments-sui's generated vectors; `quote::tests` fails if the encoding drifts.
- **Exact amounts, rounded up.** `money::pence_to_units` never produces a coin amount worth less than the GBP price
  (property-tested). No floating point touches an amount (CoinGecko's float is formatted to 12 places before parsing).
- **No quote without agreement.** At least `PRICE_MIN_SOURCES` of the free sources must answer within
  `PRICE_MAX_SPREAD_BPS`; otherwise the checkout gets 503 and no quote.
- **A payment counts only on-chain.** `chain-sui` confirms a digest when the effects succeeded and the package's `Paid`
  event matches merchant object, session, nonce, coin type and amount. A session is paid once (a unique index); a second
  payment is recorded as rejected, never as a second sale.
- **Secrets are files, never values in the environment, logs or output.** `keygen` writes a seed (0600) and prints the
  public key; `merchant add` writes the API key (0600). API keys are stored as SHA-256 only.
- **Two ports.** Public (8080, the only one behind an Ingress): read a session, quote, submit a digest; CORS only for
  `ALLOWED_ORIGINS`. Merchant (8081, cluster-internal): sessions with an API key, metrics.
- **One writer.** The worker holds a PostgreSQL advisory lock; webhooks are an outbox written in the same transaction as
  the state change and delivered at least once (`chain-payments-event-id` lets merchants deduplicate).
- **No `unsafe`**, no `unwrap`/`expect` on request paths, no SQL outside `crates/store`, dynamic SQL only via
  `AssertSqlSafe` with a reason.

## Commands

```bash
bash scripts/test-postgres.sh start && . "${TMPDIR:-/tmp}/chain-payments-test-pg/env.sh"
cargo +stable test --workspace --locked
cargo +stable clippy --workspace --all-targets --locked -- -D warnings && cargo +stable fmt --check && cargo deny check
LIVE_SUI=1 cargo +stable test -p chain-payments-chain-sui live          # the recorded transaction, live
bash scripts/e2e-testnet.sh                                             # a real testnet payment end to end (release check)
docker build -t chain-payments-service:dev . && bash scripts/smoke.sh chain-payments-service:dev
```

## Documentation and configuration rules

- `missing_docs` and `clippy::missing_docs_in_private_items` are `deny` in `[workspace.lints]`: every item, field and variant has a `///` comment.
- Migrations in `crates/store/migrations/` are never edited, not even a comment: sqlx checksums each applied file and refuses to start when it changes.
- A URL is never repeated whole in a message, a log or a stored error (it can carry a credential): `chain_payments_store::config::describe_url` names its origin,
  and `reqwest` errors go through `without_url`. The webhook addresses and the full-node URLs are the ones that matter here.

## Adding a chain

A crate `crates/chain-<name>` with `verify_payment(digest, expected)`, a `chain` value in `registry.rs`, the on-chain
program in its own repository (`chain-payments-<name>`), the client's subpath (`@meddleware/chain-payments-client/<name>`).
Merchants and checkouts need no change: methods come from the registry.

Commit messages: one short line, no body, no trailer.
