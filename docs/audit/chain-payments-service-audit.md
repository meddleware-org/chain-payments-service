# Security Audit — `chain-payments-service`

**Classification:** Internal security review (first pass, awaiting external review)
**Project:** chain-payments-service  (self-hosted crypto payment provider: merchant checkout sessions priced in GBP,
  ed25519-signed exact quotes from an agreed price median, on-chain verification of payments by digest over Sui gRPC-web, a
  single-writer worker, a signed webhook outbox, merchant API keys, PostgreSQL)
**Project type:** Rust service (+ container image + a real-chain test script)
**Template:** AUDIT_TEMPLATE.md (2026-11-01) + AUDIT_TEMPLATE_RUST.md (2026-10-08) + AUDIT_TEMPLATE_SUI_CLIENT.md (2026-10-08) +
  AUDIT_TEMPLATE_AUTH.md (2026-10-08) + AUDIT_TEMPLATE_DB.md (2026-10-25) + AUDIT_TEMPLATE_IMG.md (2026-10-08) +
  AUDIT_TEMPLATE_OPS.md (2026-10-08, `scripts/e2e-testnet.sh` only)
**Deployment status:** unreleased (no tag; `0.0.1` in `Cargo.toml`). The image `quay.io/meddleware-org/chain-payments-service`
  is not published: `config/images.yaml` digest `""`, so nothing runs in the cluster yet. The deployment is prepared in
  `post-bootstrap/chain-payments/` and the database and keys are provisioned (SOPS, 2026-11-16). Testnet: verified end to end
  2026-11-16 against the throwaway TEST merchant (`scripts/e2e-testnet.sh`).
**Review date:** 2026-11-17
**Reviewer:** Internal review
**Severity ceiling:** High — the service decides whether a payment counts, signs the quotes that set every price, and holds
  the keys merchants trust for webhooks. A verification flaw credits unpaid checkouts; a quoting flaw misprices every sale.
  Realised ceiling at this pass: **Medium** (F24, a paid transaction that is never submitted is never recognised, DEFERRED;
  F1 and F2 were Medium and are RESOLVED).
**Status:** first-pass baseline

**Toolchain:** `rust-version = "1.94"` (MSRV job), stable in CI   **Edition:** 2024
**Crates published:** no (`publish = false`)
**Runtime:** tokio multi-thread; axum 0.8.9 (http1); reqwest 0.13.5 with rustls 0.23.46 (ring), `https_only` towards the full
  node and the price sources
**Sui SDK:** none: gRPC-web through `access-gate-gateway-core` 0.0.33 (the platform's one protobuf/gRPC implementation)
**Transport:** gRPC (`LedgerService/GetTransaction`); no JSON-RPC
**Networks:** testnet today; any network named in `methods.json` with an https `SUI_GRPC_<NETWORK>`
**On-chain packages consumed:** testnet `chain_payments` `0x5f67…bc14` (original-id = published-at, version 1) and merchant
  `0x29d6…63f8`, from `METHODS_FILE` (the workspace's `overlays/default/files/methods.json`); one field for both uses (F29)
**Auth role(s):** issuer of merchant API keys (opaque bearer); verifier of them; ed25519 signer of quotes and webhooks
**Identity provider:** none
**Token formats:** opaque `cpk_` + 48 hex (192 random bits), stored as SHA-256
**Signing / client credentials:** `quote.key`, `webhook.key` (32-byte seeds, Secret `chain-payments-keys`, mounted files,
  rotation by `k8s/scripts/new-chain-payments-secrets.sh keys --force`); `chain-payments-merchant-link-in-bio` (merchant #1's
  API key, shared with the `link-in-bio` namespace)
**Authorization model:** static: an API key names one merchant; a session id is a capability for its public endpoints
**Database:** PostgreSQL on the shared tier (namespace `database`), database `chain_payments`, schema `cp`
**Roles:** `chain_payments_migrate` (owner, DDL; migrate Job; `connection_limit=2`, `statement_timeout=60s`,
  `idle_in_transaction_session_timeout=60s`) · `chain_payments_app` (writer, DML on `cp`; api, worker and the merchant-add Job;
  `connection_limit=18`, `statement_timeout=10s`, `idle_in_transaction_session_timeout=30s`) — `k8s/…/database/services.conf`
**Migrations:** sqlx `migrate!` embedded (`crates/store/migrations/0001_init.sql`, `0002_payment_claims.sql`), checksummed,
  applied under sqlx's advisory lock by the `migrate` CronJob template before the workloads roll (`apply.sh`)
**Data classes:**

- internal: merchants (name, webhook URL, enabled methods, key hash), sessions (amount, description, merchant metadata),
  quotes (with the price record), payments, webhooks;
- secret-adjacent: `api_key_hash`;
- personal: the payer's chain address on confirmed payments (public on-chain anyway), plus whatever a merchant puts in
  `metadata` (Link in Bio: its own checkout id only).

**Backups:** included in the shared tier's backup (platform); no restore drill of this database yet (pre-mainnet)
**Images:** `quay.io/meddleware-org/chain-payments-service` (not yet pushed; F31)
**Base images:** `docker.io/library/rust:1-slim@sha256:4df2ae8c…` (build) · `gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc5…` (runtime)
**Runtime user:** 65532 (distroless nonroot)   **Runtime FS:** read-only root; no writable mount
**Deployed by:** `post-bootstrap/chain-payments/overlays/default` (tag `0.0.1` until the digest exists; F31)
**Build args:** `VERSION`, `VENDOR`, `DESCRIPTION`, `SOURCE_URL`, `DOCUMENTATION_URL`, `IMAGE_URL` (labels only; none secret)
**CLI tools:** sui 1.81.0 (`e2e-testnet.sh`)   **Networks targetable:** testnet (chain id checked, F9)
**Key material:** the operator's active `sui` address (testnet, a few MIST); the public TEST quote key

---

## Executive summary

The service turns a merchant's GBP price into an exact coin quote, and a transaction digest into a "paid" checkout.
Payments are verified the right way:

- The verifier reads the transaction by digest and requires successful effects.
- It matches the event type against `<package>::chain_payments::Paid` in full after normalisation, never by suffix.
  This is the lesson of the gateway's forged-consume bug.
- It compares every quote field the event carries.
- A session is paid once, enforced by a unique index.

The quote message is byte-identical to the Move package's (shared vectors, all four messages and signatures). No quote is
issued without two agreeing price sources.

Webhooks:

- They use asymmetric ed25519 signatures over `<t>.<body>`, re-signed on every attempt, from an outbox written in the same
  transaction as the payment.
- Merchant API keys are 192-bit random and stored as SHA-256.
- SQL is parameterised throughout, and database TLS is `verify-full` only.

**This pass fixed inline (all with tests, 35 passing against PostgreSQL over TLS):**

- **F1 (Medium):** the payment record was keyed by digest alone. Anyone who read a `Paid` event could submit its digest
  against another quote of the same session first, get it rejected, and leave the real payment unrecognised. Claims are
  now `(digest, nonce)` and independent (migration 0002).
- **F2 (Medium):** an hour of full-node RPC errors rejected real payments permanently. Only a transaction that no node
  knows is now given up on.
- **F3:** the API's immediate check and the worker race on every submission, and the loser told the payer "rejected".
- **F4:** units and the subscription reference are now also verified.
- **F5:** a single price source was allowed by configuration.
- **F6:** requests had no time or concurrency bound.
- F7 to F11: `forbid(unsafe_code)`, `SECURITY.md`, the e2e script's chain-id preflight, the webhook-key rotation runbook,
  and the ADR drift.

**Open, most important first:**

1. **F24 (Medium)** — if the payer's browser never submits the digest (closed tab, network error after signing), nothing
   finds the payment. The worker settles only submitted digests (FU-0124).
2. **F28 (Low; OQ1)** — a payment that lands for a session already paid or cancelled is kept, recorded as rejected, and the
   merchant is not told (FU-0127).
3. F25, F26, F27, F29, F30 and F31 (Low): bogus-claim bounds, per-process roles and keys, the package-id split before the
   first upgrade, negative vectors, and the first release with a digest-pinned deployment.

**Dispositions (31 findings):** RESOLVED 11 · MITIGATED 1 · ADJUDICATED 1 · DEFERRED 8 · Positive 10.
**Counts by severity:** Medium 3 · Low 15 · Info 3 · Positive 10.

**Posture:** sound verification and signing core, careful configuration, and strict TLS and key handling. The remaining work
is mostly about payments the service never hears of (F24, F28) and least privilege between its own processes.

## Threat model / trust boundaries

| Actor | Holds / controls | Can do | Bounded by |
| --- | --- | --- | --- |
| Buyer's browser (public API) | a session id (32 hex, 128 random bits) | read the session, ask ≤ 30 quotes, submit claims, read claim status | session id as capability; quote cap; ingress 5 r/s per IP; body ≤ 4 KiB; 64 concurrent / 30 s per process (F6) |
| Anyone reading the chain | every `Paid` event's session id, nonce, digest | the buyer's public-API powers for that session once paid | claims are independent (F1); a paid session takes no new sale (unique index) |
| Merchant backend (merchant API, in-cluster) | its API key | create, read, cancel its own sessions | key → one merchant; sessions filtered by merchant id; NetworkPolicy (link-in-bio pods only) |
| Merchant's webhook endpoint | its responses | delay or refuse deliveries | at-least-once retries with backoff, 20 attempts, alerting |
| Sui full node | transaction effects and events | lie about or withhold a transaction | https with webpki roots; full-type event match; a lying node is a trust assumption (Risks) |
| Price sources (Kraken, Coinbase, CoinGecko) | the samples | move one sample | median of ≥ 2, all within 200 bps, or no quote (F14) |
| `MerchantCap` holder on-chain | the merchant's quote key and minimums | sign quotes with another key | the service compares units and reference too (F4); the chain's minimums |
| Operator / cluster | Secrets, ConfigMaps, the `merchant add` CLI | everything | platform custody (PLATFORM lens) |

**Primary trust anchor:** the transaction's own effects and its full-typed `Paid` event, bound to a quote this service
signed with its key (merchant object, session, nonce, coin type, amount, units, reference).

### Service actor matrix (RUST lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Network client | request line, headers, ≤ 4 KiB (public) / 16 KiB (merchant) bodies, timing | `DefaultBodyLimit`; nginx `client-max-body-size 4k`; `TimeoutLayer` 30 s; `ConcurrencyLimitLayer` 64 (F6); hyper's header limits |
| Upstream services (price sources, merchant webhook endpoints) | response size, status, timing | 6 s / 10 s timeouts, no redirects, no proxy; price bodies ≤ 64 KiB; webhook responses not read |
| Sui full node (gRPC-web) | frames the decoder parses | `access-gate-gateway-core` decoder: frame and message caps (`MAX_GRPC_MESSAGE_BYTES`), bounded varints and recursion (`MAX_VALUE_DEPTH`), required `grpc-status`; fuzzed in that crate |
| Shared state (PostgreSQL) | claim and session state; availability | row locks and status predicates; readiness fails on loss (DB lens) |
| Ingress in front | which address is the client | nginx trusts `X-Forwarded-For` only from cloudflared on the node (`set-real-ip-from 192.168.200.20/32`) |
| Crate registry / build | compiled code | `Cargo.lock`, `cargo deny` (advisories, licences, bans, crates.io only), `--locked` |

### Identity & credential matrix (AUTH lens)

| Authority / credential | Holder | What it confers | Misuse impact | Rotation / revocation |
| --- | --- | --- | --- | --- |
| Quote signing seed | api and worker pods (mounted file) | quotes every merchant's on-chain key accepts | sell at any price down to each merchant's on-chain minimum | new key + `set_quote_key` on every merchant (README Rotation); F27: the worker should not hold it |
| Webhook signing seed | api and worker pods | webhooks every merchant accepts | forge `session.paid` and get products for free | rotate; merchants re-read the key (restart Link in Bio, F10); F27: the api holds the seed but needs only the public key |
| Merchant API key | the merchant backend (Secret) | create, read and cancel that merchant's sessions | create checkouts in the merchant's name; read their metadata | `merchant rotate-key`; `disabled` flag |
| Session id | buyer's browser; public on-chain after payment | the public API for one session | quotes and claims for that session (F25) | expires (≤ 24 h) |
| Database password (`chain_payments_app`) | api, worker, merchant-add (Secret) | DML on `cp` | rewrite merchants, sessions and claims (F26) | `new-service-db-secret.sh --force` |

### Database actor matrix (DB lens)

| Actor / asset | Power | Bounded by |
| --- | --- | --- |
| api process (`chain_payments_app`) | DML on every `cp` table, merchants included | one shared writer role (F26); no DDL; `statement_timeout=10s` |
| worker process (same role) | the same | the same |
| merchant-add Job (same role) | inserts merchants | the same; operator-run, suspended CronJob |
| migrate Job (`chain_payments_migrate`) | schema | runs before the rollout; embedded, checksummed migrations |
| Request author | values in queries; page sizes | bound parameters only; fixed `LIMIT`s (50 claims, 20 webhooks) |
| Another service on the tier | connections, locks | per-role connection limits; `REVOKE … FROM PUBLIC` by the provisioner; its own database |
| Backup storage | a full copy | platform backup controls |

### On-chain dependency matrix (SC lens)

| Object / package | ID (testnet) | Sourced from | Used as | If stale, wrong or attacker-supplied | Fails |
| --- | --- | --- | --- | --- | --- |
| `chain_payments` package | `0x5f67…bc14` | `methods.json` `packageId` | event-type filter (`<id>::chain_payments::Paid`); also handed to the checkout as the call target | an upgraded id in the event filter matches nothing (F29) | closed |
| `Paid` event type | `0x5f67…bc14::chain_payments::Paid` | derived | full-type filter | a look-alike package's `Paid` is ignored (F12) | closed |
| Merchant object | `0x29d6…63f8` | `methods.json` `merchantObject` | the event's `merchant_id` must equal it; signed into the quote | a wrong merchant refuses the quote's signature on-chain | closed |
| Coin types | `0x2::sui::SUI`, `0xa1ec…7e29::usdc::USDC` | `methods.json` (canonicalised) | signed; compared with the event | — | closed |

### Image supply-chain matrix (IMG lens)

| Actor / asset | Power | Bounded by |
| --- | --- | --- |
| Base-image publishers | base layers | both `FROM`s digest-pinned; distroless runtime |
| Build context | files copied in | `.dockerignore` excludes `target`, `.git`, `.github`, `*.md`, `.env*` |
| Build args | labels | none secret |
| Registry | the manifest for a tag | deployment by digest (pending first release, F31); cosign keyless signature |
| CI publish job | what is pushed | Trivy scan before sign; SBOMs (SPDX + CycloneDX checked against `Cargo.lock`); provenance |
| Manifests | how it runs | non-root 65532, read-only root, no privilege escalation, all capabilities dropped, `RuntimeDefault` seccomp, no service-account token, no service links |

### Operations (OPS lens, script inventory)

| Script / job | Signs? | Objects touched | Irreversible? | Dry-run default | Confirmation | Network guard | Writes IDs to |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `scripts/e2e-testnet.sh` | yes (one `pay` on testnet, about a penny) | the TEST merchant's nonce and ledger | no | no (a test) | none (testnet only) | active env `testnet` **and** chain id `4c78adac` (F9) | nothing |
| `scripts/smoke.sh`, `test-postgres.sh`, `check-*.sh` | no | — | — | — | — | — | — |

## Severity scale

Critical / High / Medium / Low / Info / Positive.

## Scope

**In scope (`main` = `678192f` plus this pass's changes):**

- `crates/core/src/{money,price,quote,registry,session,webhook}.rs`
- `crates/chain-sui/src/lib.rs`
- `crates/store/{src/lib.rs,src/config.rs,migrations/*.sql}`
- `crates/service/src/{api,app,config,metrics,prices,worker}.rs` and `crates/service/tests/api.rs`
- `crates/cli/src/main.rs`
- `Cargo.toml`, `Cargo.lock`, `deny.toml`, `Dockerfile`, `.dockerignore`
- `.github/workflows/{rust-ci,docker-publish}.yml`, `.github/dependabot.yml`
- `scripts/*.sh`, `fixtures/*`, `SECURITY.md`, `README.md`, `CHANGELOG.md`

**Cross-repo evidence (read-only unless noted):**

- `chain-payments-sui` (the Move package and vectors);
- `post-bootstrap/chain-payments/` (network policy, Deployments, HPA, ingress, merchant-add, `config.env`, `methods.json`;
  the README's rotation note corrected, F10);
- `k8s/clusters/meddleware-org/database/services.conf`;
- `k8s/base/infrastructure/nginx-ingress/values.yaml` (real-IP trust);
- `k8s/…/monitoring/vmalert/rules/alerts.yaml` (group `chain-payments`);
- `repos/link-in-bio-service/crates/billing/src/chain_payments.rs` (the merchant side);
- `docs/architecture/ADR-0011-chain-payments.md` (amended, F11).

**Out of scope:** `access-gate-gateway-core`'s decoder (its own audit, fuzz targets in `core/fuzz`); the shared PostgreSQL
tier and its backups (platform audit); Link in Bio's billing as a whole.

**Environment / commands (2026-11-17):**

| Command | Result |
| --- | --- |
| `cargo +stable test --workspace --locked` against the throwaway PostgreSQL (TLS `verify-full`, `REQUIRE_TEST_DATABASE=1`) | **35 passed, 0 failed, 0 ignored** (core 10, chain-sui 3, service 6 + api 3, store 13) |
| `cargo +stable clippy --workspace --all-targets --locked -- -D warnings` | clean |
| `cargo +stable fmt --check` | clean |
| `cargo deny check` | advisories ok, bans ok, licences ok, sources ok |
| `cmp fixtures/quote-vectors.json ../chain-payments-sui/tests/vectors.json` | identical |
| Image build, Trivy, `scripts/smoke.sh` | **not run** (no container builds in the review environment); CI runs all three on every push |
| `cargo llvm-cov` | not run this pass; CI publishes the line coverage summary |

## Findings

### F1 — Whoever submitted a digest first chose the quote it was checked against

**Severity:** Medium   **Disposition:** RESOLVED
**Where:** `crates/store/migrations/0001_init.sql` (`cp.payments.digest` was the primary key); `Store::submit_payment`
(`ON CONFLICT (digest) DO NOTHING`); `App::settle(digest)`; `api::post_payment`.
**Issue:** A submission names a digest and a quote nonce. The record was keyed by the digest alone, so the first submission
fixed the nonce for good, and a later one was a no-op. Every `Paid` event publishes its session id and nonce on-chain.
After a payment executes, an observer can:

1. read the event;
2. request a second quote for the same session (the session id is now public, and the session is still open);
3. post `{nonce: <second quote>, digest: <the real digest>}` before the buyer's checkout does.

The check then finds no event for the second nonce and rejects the record. The buyer's own submission changes nothing, and
the payment is never credited.
**Impact:** The buyer pays and gets nothing; the merchant receives the coin but no webhook. The attacker needs only to
watch the chain and win a short race against the checkout's submission. It costs them nothing and works against every
payment.
**Remediation / evidence:**

- A record is now a claim `(digest, nonce)`. Migration `0002_payment_claims.sql` moves the primary key and adds an index on
  `session_id`.
- Every store call takes both values. `settle(digest, nonce)` checks one claim.
- `GET /v1/sessions/{id}/payments/{digest}` reports the best status among the session's claims of that digest (confirmed,
  then pending, then rejected).
- One transaction may now also legitimately pay several quotes.
- Test: `store::tests::a_wrong_claim_of_a_digest_cannot_block_the_right_one` (the attacker's claim is rejected, the buyer's
  claim of the same digest is confirmed, and the session is paid), plus `best_status_prefers_confirmed_then_pending` and
  the API's 404 for an unknown claim.
- No release ever ran 0001 alone (no image exists), so no running process depends on the old key (DB-M2 holds).

### F2 — A full-node outage of an hour rejected real payments for good

**Severity:** Medium   **Disposition:** RESOLVED
**Where:** `crates/service/src/app.rs::settle` (the `retryable` branch); `GIVE_UP_AFTER_SECS = 3600`.
**Issue:** "Not found" and RPC failures were both retryable, and both became a permanent rejection once the claim was an
hour old.
**Impact:** If the configured full node (`fullnode.testnet.sui.io`, a public endpoint) or its egress is down for an hour,
every payment submitted in that hour is rejected and never credited.
**Remediation / evidence:** `app::gives_up` ends a claim only for `VerifyError::NotFound` older than an hour, meaning no node
knows the transaction. RPC errors keep retrying with the capped backoff (≤ 300 s), and `ChainPaymentsPaymentsPending`
alerts after 30 minutes. Test: `app::tests::only_an_unknown_transaction_is_given_up_on`.

### F3 — Two processes settling the same claim told the buyer "rejected"

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `App::settle`; `Store::confirm_payment` returned `false` both for "the session was already paid" and for "this
claim is no longer pending".
**Issue:** `submit_payment` inserts the claim with `next_check_at = now()`, so the worker's next tick (every 3 s) sees it as
due while the API is still running its immediate check. Whichever confirms second took the `false` branch and answered
`rejected`.
**Impact:** The buyer's checkout showed "That transaction did not pay this checkout" and emitted `failed` after a payment
that was in fact confirmed (the merchant got its webhook). The rejected-payments metric was also inflated.
**Remediation / evidence:** `confirm_payment` returns `Settled::{Confirmed, NotOpen, Already(status)}`. The loser of the race
returns the winner's status and counts nothing. Test: `store::tests::a_confirmed_payment_pays_the_session_once_and_queues_one_webhook`
(a second settlement reports `Already("confirmed")`).

### F4 — Verification did not compare units and the subscription reference

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `crates/chain-sui/src/lib.rs::check_response`, `Expected`.
**Issue:** The event was matched on merchant, session, nonce, coin type and amount. Nonce uniqueness implies the rest only if
the service's key is the only one the merchant trusts. A `MerchantCap` holder (a thief, before the recipient delay) can set
another quote key and sign a quote with the session's nonce and amount but 120 units and its own reference.
**Impact:** Small today. Link in Bio credits the months from its own checkout, not from the event (`months: None`), but the
webhook's `paidUntilMs` and the on-chain ledger would disagree with the sale.
**Remediation / evidence:** `Expected` carries the session's `units` and `subscription_ref`, and both must match. A reference
that is absent in the rendered event counts as empty only when an empty one is expected. `Confirmed.units` is the session's.
Test: `recorded_payment_is_confirmed_and_any_difference_is_not` (units 2, reference `acct-other` and an empty reference are
all refused against the recorded testnet transaction).

### F5 — One price source was accepted by configuration

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `crates/service/src/config.rs` (`PRICE_MIN_SOURCES` bounded 1–3).
**Issue:** ADR-0011 §3 requires "at least two". With `PRICE_MIN_SOURCES=1`, a quote could rest on one source with nothing to
agree with (the spread of one sample is 0).
**Impact:** A single manipulated or broken source would set prices. The deployed `config.env` says 2, so this was latent.
**Remediation / evidence:** The bound is now 2–3, and fewer configured sources than that is refused at start. Tests:
`config::tests::a_single_price_source_is_never_enough`, `defaults_are_accepted`, `doubtful_values_are_refused`.

### F6 — Requests had no time or concurrency bound

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `crates/service/src/api.rs` (routers); `tower`/`tower-http` with `timeout` and `limit` were dependencies but
unused.
**Issue:** RUST lens §A *HTTP hygiene*: no handler timeout, and no concurrency limit sized against memory.
**Impact:** Slow upstreams (price sources at 6 s, the full node at 10 s, DB pool waits at 5 s) let requests pile up inside a
128 MiB pod.
**Remediation / evidence:** Both routers get `TimeoutLayer` (30 s, `408`) and `ConcurrencyLimitLayer(64)`. Body caps are
4 KiB and 16 KiB, so 64 requests hold well under a megabyte; the DB pool (4) and the full node queue behind the limit.
Existing router tests pass through the layers.

### F7 — `unsafe_code` was `deny`, not `forbid`

**Severity:** Info   **Disposition:** RESOLVED
**Where:** `Cargo.toml` `[workspace.lints.rust]`.
**Issue:** `deny` can be overridden by a local `allow`. There is no `unsafe` in the workspace.
**Remediation / evidence:** `unsafe_code = "forbid"`. Clippy and the build are clean.

### F8 — `SECURITY.md` lacked required sections and the merchant's webhook duties

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `SECURITY.md`.
**Issue:** No Supported versions or Disclosure sections. The model did not say what a merchant must check on a webhook, or
that a submission is a claim.
**Remediation / evidence:** The policy is rewritten with the five sections. The model covers full-type verification, claims,
two price sources, 192-bit keys, request bounds, and the merchant's webhook duties (signature, ±5 minutes, idempotency by
event or session id, only its own sessions).

### F9 — The live script trusted the env's name

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `scripts/e2e-testnet.sh`.
**Issue:** It checked `sui client active-env == testnet` only (OPS §A *Preflight*: the chain identifier must match too).
**Remediation / evidence:** It now hard-fails unless `sui client chain-identifier` reports `4c78adac`, the format checked
against the CLI on 2026-11-17. `bash -n` is clean; shellcheck runs in CI.

### F10 — The rotation runbook said merchants re-read the webhook key

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `post-bootstrap/chain-payments/README.md` (Rotation); `link-in-bio-service/crates/billing/src/chain_payments.rs`
(`OnceCell` key cache).
**Issue:** Link in Bio fetches `/v1/webhook-key` once per process and keeps it. After a rotation, every webhook fails its
signature check until Link in Bio restarts.
**Impact:** Deliveries are retried, not lost, but payments are credited late. The runbook gave no step for it.
**Remediation / evidence:** The README now says to restart Link in Bio's Deployments after the Chain Payments pods roll, and
why.

### F11 — ADR-0011 described other price sources and crates than were built

**Severity:** Info   **Disposition:** RESOLVED
**Where:** `docs/architecture/ADR-0011-chain-payments.md` §1 and §3.
**Issue:** The ADR named DeepBook × Frankfurter and crates `api` and `watcher`. The code uses Kraken, Coinbase and CoinGecko,
all in GBP, and one `service` crate.
**Remediation / evidence:** A dated *Amendment 2026-11-17 (as built)* records the sources, the two-source minimum and the
crate layout.

### F12 — Payment verification: digest-first, full-type, every bound field, fail closed

**Severity:** Positive
**Where:** `crates/chain-sui/src/lib.rs::{verify_payment, check_response}`.

- Reads `LedgerService/GetTransaction` by a validated base58 digest and requires `effects_succeeded`.
- Iterates the events and keeps only those whose type, normalised, equals
  `normalize_move_type("<package>::chain_payments::Paid")`. A look-alike `Paid` from any other package is ignored, which is
  the fix pattern of the gateway's 2026-10 forged-consume bug.
- Then compares: merchant id (normalised address), session and nonce (base64 bytes), canonical coin type, amount, units and
  reference (F4).
- The payer is the normalised event field.
- A missing transaction is `NotFound` (retry); missing fields do not match. Decoding bounds are in the shared core crate.
- Test: the recorded testnet transaction is confirmed, and every single-field difference is refused (amount, session,
  nonce, merchant, package, coin type, units, reference).

### F13 — Quote signing is byte-identical to the Move package

**Severity:** Positive
**Where:** `crates/core/src/quote.rs`.
`QuoteFields::message` implements the domain tag and BCS layout of `chain_payments::quote_message`:

- the merchant id is decoded to exactly 32 bytes;
- identifiers are 1–64 bytes, the reference ≤ 64;
- the coin type must already be canonical (64 hex digits, no `0x`, `::module::Name`).

`matches_the_move_package_vectors` asserts all four shared messages and signatures (seed `0x01`×32). The fixture equals the
Move repo's file at review (`cmp`). Signing uses `ring` ed25519 from a 32-byte seed. One service key serves every merchant;
the merchant object id inside the message keeps a quote to its merchant. Negative vectors and a drift check: F30.

### F14 — Price manipulation: the source-agreement guard

**Severity:** Positive
**Where:** `crates/core/src/price.rs::agree`; `crates/service/src/prices.rs`; `crates/core/src/money.rs`.

- **Sources:** each queried in GBP over https with no redirects and a 6 s timeout. Bodies are ≤ 64 KiB. Each reply is
  shape-checked: Kraken requires `bid ≤ ask` and uses the mid; Coinbase requires `currency == GBP`; CoinGecko requires a
  finite positive number.
- **Agreement:** zero samples are dropped. At least `min_sources` (now ≥ 2, F5) must answer, and the whole spread must be
  ≤ 200 bps, or there is no quote (`503`, metric, alert `ChainPaymentsNoPrice`). The quote is the median.
- **Conversion:** fixed point (pico-pounds), rounding the coin amount up. A property test shows a quote is never worth less
  than the price.
- **Bounds:** the agreed price is cached ≤ 30 s, and every quote stores its samples (the valuation record).
- **Residual:** a coordinated move of all sources within 2 %. The merchant's on-chain minimum bounds the worst case.

### F15 — Webhooks: signature, timestamp, outbox, at-least-once

**Severity:** Positive
**Where:** `crates/core/src/webhook.rs`; `crates/service/src/worker.rs::deliver`; `Store::{confirm_payment, expire_sessions,
claim_webhooks}`.

- The event is written to `cp.webhooks` in the same transaction as the state change.
- The worker claims due rows `FOR UPDATE SKIP LOCKED` with a 60 s lease.
- Each delivery signs `t=<now>,ed25519=<sig over "<t>.<body>">` afresh, with the event id in the body (signed) and in
  `chain-payments-event-id`.
- A 2xx response marks the event delivered. Otherwise it backs off exponentially, capped at 6 h, for 20 attempts, then
  stays in the outbox for a person (`ChainPaymentsWebhooksBacklog`, `ChainPaymentsWebhookFailures`).
- The client follows no redirects, uses no proxy, and has 5 s / 10 s timeouts.
- The signing key is asymmetric, so merchants hold no secret.
- Link in Bio verifies the signature and a ±300 s window, and is idempotent on `paid:<session>`
  (`link-in-bio-service/crates/billing/src/chain_payments.rs`).

### F16 — A webhook does not name the merchant it is for

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `worker::deliver` body `{id, event, data}`; one webhook key for every merchant.
**Issue:** Merchant A's signed webhook, replayed within five minutes to merchant B's endpoint, verifies there too.
**Impact:** None for a merchant that accepts only its own sessions. Link in Bio maps `sessionId` to one of its own checkouts
(`provider_ref`) before acting. Today there is one merchant. `SECURITY.md` now makes "accept only sessions you created" a
merchant duty (F8). Adding `merchantId` to the payload is a suggestion.

### F17 — Webhook URLs could reach any https host (SSRF)

**Severity:** Low   **Disposition:** MITIGATED
**Where:** `worker::webhook_url_allowed` (https anywhere; http only to `*.svc` / `*.svc.cluster.local`); the database CHECK
constraint.
**Issue:** The code would POST to `https://10.x/…` or a link-local address if a merchant were configured so.
**Impact:** The worker sends a signed POST to an internal address. This needs the operator: merchants are created only with
the CLI (`merchant add`, a suspended CronJob) and never through the API.
**Remediation / evidence:** `egress-webhooks` (CiliumNetworkPolicy) lets the worker reach only `link-in-bio-api:8081`;
everything else is dropped. Credentials in the URL are refused, and redirects are not followed. Before any self-service
merchant exists, the code must also refuse IP-literal and private hosts. That is recorded in OQ2 / FU-0126's note on
merchant onboarding.

### F18 — Merchant API keys

**Severity:** Positive
**Where:** `crates/cli/src/main.rs` (`cpk_` + `random_id(24)`, mode 0600, never printed); `k8s/scripts/new-chain-payments-secrets.sh`
(`openssl rand -hex 24`); `Store::{hash_key, merchant_by_key}`; `api::merchant_of`.

- Keys carry 192 random bits, and only their SHA-256 is stored, under a unique constraint. A fast hash is appropriate for a
  key of that entropy.
- Lookup is by hash, so there is no string comparison to time.
- Disabled merchants cannot authenticate.
- The header must be `Bearer` with a key of 32–128 characters. A missing or unknown key gets `401` with a uniform body
  before the request body is read.
- Rotation is `merchant rotate-key`.
- Test: `keys_are_hashed_and_disabled_merchants_cannot_authenticate`.

### F19 — Database: query safety, transport, redaction, availability

**Severity:** Positive
**Where:** `crates/store/src/{lib.rs,config.rs}`; `services.conf`; `api::readyz`.

- **Queries:** every one is a static string with bound parameters. The only spliced SQL is test-only (`CREATE DATABASE`
  from a UUID). Listings have fixed `LIMIT`s.
- **Transport:** `DATABASE_URL` must be `sslmode=verify-full` with `sslrootcert`. Anything weaker is refused unless
  `ALLOW_INSECURE_DATABASE=1`, and only `sslmode`, `sslrootcert` and `application_name` parameters are accepted.
- **Redaction:** `Debug` and every error hide the password, and statement logging is off.
- **Integrity in the database:** session status, webhook events and claim status are check-constrained. "A session is paid
  once" is a partial unique index.
- **Availability:** the pool connects lazily. `/readyz` fails when the database does not answer, `/healthz` does not (DB-M8).
  The role's `statement_timeout` (10 s) and `idle_in_transaction_session_timeout` (30 s) bound runaways.
- Tests run on PostgreSQL over TLS with fresh databases. CI fails on a skipped database test.

### F20 — The single-writer lock is not load-bearing

**Severity:** Positive
**Where:** `worker::run` (`pg_try_advisory_lock(7_377_001)` on a held connection); `Store::confirm_payment` (`FOR UPDATE OF
p, s` + `status = 'pending'`); `claim_webhooks` (`SKIP LOCKED` + lease); `expire_sessions` (one transaction).
The API already settles claims concurrently with the worker (F3). Every state change is guarded in SQL, not by the lock. If
the lock's connection dropped and a second worker started, the worst outcome would be a duplicate webhook delivery, which
at-least-once delivery already allows. The deployment also runs one worker with `Recreate`.

### F21 — Abuse limits: rate limits, CORS, quote flooding

**Severity:** Positive
**Where:** `post-bootstrap/chain-payments/base/ingress.yaml`; `api::public_guard`; `App::quote`.

- **Ingress:** nginx limits 5 r/s per client address (burst 20, `429`), keyed on the real client IP. `X-Forwarded-For` is
  trusted only from cloudflared on the node (`set-real-ip-from 192.168.200.20/32`).
- **Exposure:** only `/v1/sessions/` is routed publicly, with bodies ≤ 4k. The merchant API, metrics and webhook key stay
  in the cluster (NetworkPolicies).
- **CORS:** exact origins from `ALLOWED_ORIGINS`; a preflight from any other origin gets `403`.
- **Headers:** no cookies (`Set-Cookie` stripped), `no-store`, `nosniff`, `no-referrer`,
  `CSP default-src 'none'; frame-ancestors 'none'`.
- **Quotes:** at most `MAX_QUOTES_PER_SESSION` (30) per session, sessions only by merchants, prices cached 30 s.
- Tests: `cors_only_for_configured_origins_and_no_cookies`, `a_checkout_reads_its_session_and_gets_exact_quotes` (the quote
  limit).

### F22 — Image and pod hardening

**Severity:** Positive
**Where:** `Dockerfile`; `post-bootstrap/chain-payments/base/*.yaml`.

- **Image build:**
  - both bases are digest-pinned, with a distroless `cc` runtime (no shell);
  - `cargo-chef` 0.1.78 and `cargo-about` 0.9.2 are installed `--locked`, and the binary is built `--locked`;
  - the `cargo-about` notices stage fails on an unaccepted licence;
  - `Cargo.lock` is copied in so scanners list the crates;
  - `USER 65532`.
- **Every pod:**
  - `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities dropped,
    `RuntimeDefault` seccomp, `automountServiceAccountToken: false`;
  - limits of 500m / 128 Mi;
  - liveness on `/healthz` and readiness on `/readyz` (api).
- **Secrets:** keys mounted `0440` read-only.
- Default-deny network policy in both directions, then FQDN egress to the full node and the price hosts only.

### F23 — CI and release integrity

**Severity:** Positive
**Where:** `.github/workflows/{rust-ci,docker-publish}.yml`, `.github/dependabot.yml`, `deny.toml`.

- **Pinning:** every action by SHA; `permissions: contents: read`, with `id-token: write` only on the signing job.
- **Branch CI:** fmt, clippy `-D warnings`, tests on PostgreSQL with no skip and no ignore, llvm-cov, `cargo deny`, the SBOM
  gate, MSRV 1.94, and Trivy config and image scans (fail on fixable CRITICAL/HIGH).
- **Release:** tag-gated, and the verify job is `rust-ci.yml` via `workflow_call`, so the release gate equals CI. Images are
  scanned before signing, then signed keylessly with cosign at the index digest, with SBOM attestations (SPDX and
  CycloneDX) and provenance. The published `cosign verify` pins this repository's workflow and tag refs.
- **Mirror:** the private mirror is best-effort (`continue-on-error`) and listed as such.
- **Dependabot:** Cargo, Docker and Actions.
- Registry pushes use the quay.io and Docker Hub robot tokens; their custody is the key-custody audit's (KEY_CUSTODY rows,
  FU-0013).

### F24 — A paid transaction that is never submitted is never recognised

**Severity:** Medium   **Disposition:** DEFERRED (FU-0124)
**Where:** `worker::tick` settles only `cp.payments` rows; rows come only from `POST /v1/sessions/{id}/payments`.
**Issue:** Nothing reads the chain for `Paid` events of a registry merchant. If the buyer's tab closes, or the submission
fails after the wallet executed the transaction (network error, `503` from storage, a timeout), the payment exists only
on-chain. The kit has no retry for this case (kit audit F2).
**Impact:** The buyer paid, and the merchant received the coin, but the session expires (`session.expired` webhook) and the
buyer gets nothing until support matches the on-chain `paid_until` by hand.
**Remediation / evidence:** Two parts, tracked together in FU-0124:

- the kit keeps `{sessionId, nonce, digest}` in `sessionStorage` (scoped by session) and resubmits with backoff until it has
  an answer;
- the worker reconciles: for each open or recently expired session with quotes, it reads the merchant's `Paid` events by
  checkpoint (GraphQL `events(filter: {type})`, or a checkpoint subscription). It inserts any claim whose nonce is one of
  its quotes and settles it as usual. F1's claim model makes this safe: the event names the exact nonce.

### F25 — Claims are unbounded per session

**Severity:** Low   **Disposition:** DEFERRED (FU-0125)
**Where:** `api::post_payment`; `Store::submit_payment`.
**Issue:** Anyone who knows a session id (public on-chain once paid) can post claims with random well-formed digests and any
of the session's nonces. Each becomes a pending row. It is re-checked against the full node for an hour and holds the
session open (`expire_sessions` waits for pending claims).
**Impact:** Database growth and full-node calls. This is bounded by ingress rate limits (5 r/s per IP) and the 4 KiB body,
not by the service. There is no effect on payments.
**Remediation / evidence:** Cap pending claims per session (e.g. 5) so that the cap cannot refuse the real claim: a new claim
is settled at once, and only a claim still unknown to the node counts towards the cap. Refuse new unknown claims for
sessions that are paid or cancelled. Tracked in FU-0125.

### F26 — One writer role for the public API, the worker and merchant administration

**Severity:** Low   **Disposition:** DEFERRED (FU-0126)
**Where:** `services.conf` (`writer chain_payments chain_payments_app`); the api and worker Deployments and the merchant-add
Job all mount `chain-payments-app-db`.
**Issue:** DB lens: one role per process kind. The public-facing API's role can `UPDATE cp.merchants` (webhook URL, key
hash) and `INSERT` merchants, though it only reads them.
**Impact:** A compromised API pod could redirect a merchant's webhooks (Cilium still limits egress) or mint a merchant key.
**Remediation / evidence:**

- Split into an api role (read `merchants`; write `sessions`, `quotes`, `payments`; insert `webhooks`), a worker role (no
  `merchants` write) and an admin role for `merchant add` and `rotate-key`.
- Add role tests that prove each forbidden write fails.
- Tracked in FU-0126.

### F27 — Both processes hold both signing seeds

**Severity:** Low   **Disposition:** DEFERRED (FU-0126)
**Where:** `config::Config::from_env` requires `QUOTE_KEY_FILE` and `WEBHOOK_KEY_FILE` in every process; both Deployments
mount `chain-payments-keys`.
**Issue:** The worker never signs quotes. The api never signs webhooks: it serves only the webhook *public* key.
**Impact:** A worker compromise also leaks the quote key, and an api compromise the webhook seed.
**Remediation / evidence:**

- Make each key optional per subcommand: `serve` needs `QUOTE_KEY_FILE` plus `WEBHOOK_PUBLIC_KEY` (hex), and `worker` needs
  `WEBHOOK_KEY_FILE`.
- Split the Secret into two and mount each where it is needed.
- Tracked in FU-0126.

### F28 — A payment for a session that is already paid or cancelled is kept silently

**Severity:** Low   **Disposition:** DEFERRED (FU-0127; decision OQ1)
**Where:** `Store::confirm_payment` (`UPDATE … WHERE status IN ('open', 'expired')`; otherwise the claim is `rejected`);
`cp.webhooks.event` CHECK allows `session.paid` and `session.expired` only.
**Issue:** These situations all produce a valid on-chain payment for a session that can no longer be sold:

- two quotes paid from two tabs;
- a quote paid after the merchant cancelled;
- a gift that lands after the session closed.

The coin is with the merchant, the claim is `rejected`, and no event is sent. The on-chain ledger is extended, so
`paid_until` is longer than the merchant's records.
**Impact:** The buyer is charged twice, or for a cancelled order, and the merchant is not told.
**Remediation / evidence:**

- This pass made the record accurate (`last_error` "paid on-chain, but the session was no longer open"; the payer is
  recorded). Test: `a_payment_for_a_cancelled_session_is_recorded_not_sold`.
- What should happen next is a decision (OQ1): a `payment.unapplied` webhook carrying the payer and amount, so the
  merchant can refund or credit; or refunds by the operator from the merchant's recipient; or both.
- Tracked in FU-0127.

### F29 — One `packageId` feeds both the event filter and the checkout's call target

**Severity:** Low   **Disposition:** DEFERRED (FU-0123, before the first package upgrade)
**Where:** `core::registry::Method.package_id`; `App::method_json` (`packageId` to the checkout); `check_response`
(`<package_id>::chain_payments::Paid`).
**Issue:** SC lens canonical footgun: after an upgrade, calls must target the latest published-at, while the `Paid` type
keeps the original id.
**Impact:** None while version 1 is the only version. After an upgrade, one of the two uses breaks. Both fail closed:
payments would not confirm, or would call superseded code that version gating refuses.
**Remediation / evidence:** Add `publishedAt` to `Method` (call target, sent to the checkout), keep `packageId` as the
original id (type filter), and test that both are carried. Do this before FU-0121's upgrade. Tracked in FU-0123.

### F30 — The vector fixture is a copy, and the vectors have no negatives

**Severity:** Low   **Disposition:** DEFERRED (FU-0128)
**Where:** `fixtures/quote-vectors.json` (`include_str!` in `quote.rs`).
**Issue:** The file is identical to the Move repo's today (`cmp`), but nothing in CI compares them. It also has no negative
vectors (SC and AUTH lenses).
**Remediation / evidence:**

- Compare the fixture with `chain-payments-sui/tests/vectors.json` at a pinned commit in CI.
- Consume the negative vectors once the generator emits them (move audit F19).
- Tracked in FU-0128.

### F31 — No release yet; the overlay deploys a tag

**Severity:** Low   **Disposition:** DEFERRED (FU-0130)
**Where:** `config/images.yaml` (`digest: ""`); `overlays/default/kustomization.yaml` (`newTag: 0.0.1`); the deployment README
step 1 (the quay.io repository is the maintainer's).
**Issue:** IMG-M6: the deployment must run the signed index digest, not a tag.
**Impact:** None until something is deployed. A deploy before the digest is recorded would run a mutable tag, though the
policy-controller requires the image's signature.
**Remediation / evidence:**

1. The maintainer creates the quay.io repository and robot.
2. Tag `v0.0.1`; CI signs and attests the image.
3. Run `refresh-digests.sh && sync-manifests.sh` so the overlay pins `@sha256:…`.

Tracked in FU-0130.

## Section A — Invariant verification matrix

| # | Invariant | Enforced at | Proven by | Status |
| --- | --- | --- | --- | --- |
| I1 | A claim is confirmed only if the transaction succeeded and emitted `<package>::chain_payments::Paid` (full type) for the quote's merchant, session, nonce, coin, amount, units and reference | `chain-sui::check_response` | `recorded_payment_is_confirmed_and_any_difference_is_not` | HOLDS |
| I2 | A wrong claim of a digest cannot block the right one | PK `(digest, nonce)` (0002); `submit_payment` | `a_wrong_claim_of_a_digest_cannot_block_the_right_one` | HOLDS (F1) |
| I3 | A session is sold once; later payments are recorded, not sold | partial unique index `payments_one_confirmed`; `confirm_payment` | `a_confirmed_payment_pays_the_session_once…`, `a_payment_for_a_cancelled_session_is_recorded_not_sold` | HOLDS (merchant not told: F28) |
| I4 | Concurrent settlement reports the true outcome | `Settled::Already` | `a_confirmed_payment_pays_the_session_once…` | HOLDS (F3) |
| I5 | A real payment is never rejected because our node was down | `app::gives_up` | `only_an_unknown_transaction_is_given_up_on` | HOLDS (F2) |
| I6 | Every submitted payment is eventually recognised | — | — | GAP (unsubmitted payments: F24) |
| I7 | The quote message equals the Move package's, byte for byte | `quote::QuoteFields::message` | `matches_the_move_package_vectors` (4 messages + signatures) | HOLDS (negatives: F30) |
| I8 | No quote without ≥ 2 agreeing sources within the spread | `price::agree`; `config` (min ≥ 2) | `median_of_agreeing_sources`, `refuses_disagreement_and_too_few`, `a_single_price_source_is_never_enough` | HOLDS |
| I9 | The coin amount is never worth less than the GBP price | `money::pence_to_units` (round up) | `never_short` (proptest), `converts_pounds_to_coin_rounding_up` | HOLDS |
| I10 | A quote is only for an open session, an offered method, within the per-session cap | `App::quote` | `a_checkout_reads_its_session_and_gets_exact_quotes` | HOLDS |
| I11 | Webhooks are signed, timestamped, queued atomically with the change and delivered at least once | `webhook::sign`; `enqueue` in the state transaction; `claim_webhooks` lease | `round_trip_and_tampering`; store webhook tests | HOLDS |
| I12 | Merchant API keys are stored only as hashes; disabled merchants cannot authenticate | `hash_key`, `merchant_by_key` | `keys_are_hashed_and_disabled_merchants_cannot_authenticate` | HOLDS |
| I13 | The merchant API sees only its own sessions | `merchant_session` (`s.merchant_id == m.id`), `cancel_session` (`AND merchant_id`) | `cancel_session` in the cancelled-session test | HOLDS (code-only for the read path) |
| I14 | Public responses never carry merchant metadata | `get_session` builds its response field by field | `a_checkout_reads_its_session…` (`metadata` absent) | HOLDS |
| I15 | Values bound as parameters; no string-built SQL with values | `store` | inspection; every query static | HOLDS (code-only) |
| I16 | Database transport is `verify-full` only (or an explicit local switch) | `DatabaseSettings::parse` | `every_weaker_tls_setting_is_refused` | HOLDS |
| I17 | Least privilege between processes (role and keys) | — | — | GAP (F26, F27) |
| I18 | Requests are bounded in size, time and concurrency | `DefaultBodyLimit`; `TimeoutLayer`; `ConcurrencyLimitLayer` | router tests pass through the layers | HOLDS (F6; code-only for the bounds themselves) |
| I19 | No panic on attacker input; no `unsafe` | `forbid(unsafe_code)`; checked arithmetic; `release` `overflow-checks = true`, `panic = "abort"` | clippy; inspection | HOLDS (code-only) |
| I20 | Secrets never in logs or `Debug` | `Signer` Debug prints the public key; `DatabaseSettings` Debug redacts | `the_password_never_appears_in_debug_or_errors` | HOLDS |

## Section B — Supply-chain, publish-authority & capability matrix

### B.1 Dependency & CVE risk

| Dependency | Pinned version | Liveness dependency? | CVE / audit status | Notes |
| --- | --- | --- | --- | --- |
| `access-gate-gateway-core` | `=0.0.33` | verification path (gRPC-web, protobuf, normalisation) | `cargo deny` clean; fuzzed in its repo | the platform's single decoder |
| `ring` | `=0.17.14` | quote and webhook signing; RNG | clean | ed25519 signing; `SystemRandom` |
| `sqlx` | `=0.9.0` (rustls ring webpki) | every request | clean | runtime-checked queries; embedded migrations |
| `axum` / `tower` / `tower-http` | `=0.8.9` / `=0.5.3` / `=0.7.1` | API | clean | timeout and limit layers (F6) |
| `reqwest` / `rustls` | `=0.13.5` / `=0.23.46` | full node, price sources, webhooks | clean | `https_only` on chain and prices; no redirects; no proxy |
| `sha2` | `=0.11.1` | API-key hashing | clean | — |
| Sui full node `fullnode.testnet.sui.io:443` | `SUI_GRPC_TESTNET` | settlement: **retries, never rejects** on error (F2) | public endpoint | Mysten-operated |
| Kraken / Coinbase / CoinGecko public APIs | `PRICE_SOURCES` | quoting: **closed** (no quote) below two answers | — | no key, no user data sent |
| PostgreSQL tier | `services.conf` | everything: readiness fails, liveness stays up | platform | `verify-full` |
| `cargo deny check` at review | — | — | advisories, bans, licences, sources ok | `Cargo.lock` committed |

### B.2 Publish authority, capabilities & secret custody

| Authority / secret | Where held | Custody | Gates | Rotation |
| --- | --- | --- | --- | --- |
| Quote seed | Secret `chain-payments-keys` `quote.key` (SOPS in git) | node + age key | every quote | `new-chain-payments-secrets.sh keys --force`, then `set_quote_key` on each merchant |
| Webhook seed | same Secret, `webhook.key` | same | every webhook | same command; merchants re-read the key (F10) |
| Merchant #1 API key | Secret `chain-payments-merchant-link-in-bio` (both namespaces) | SOPS | Link in Bio's sessions | `merchant rotate-key` |
| DB passwords | `chain-payments-{app,migrate}-db` | SOPS | database | `new-service-db-secret.sh --force` |
| Image publish | quay.io / Docker Hub robot tokens (repository secrets) | GitHub | images | KEY_CUSTODY rows (FU-0013) |
| Cosign signing | keyless (GitHub OIDC) | Sigstore | image signatures | n/a |

#### CI & release integrity

All hold (F23): Actions pinned · least privilege · keyless signing (no registry OIDC for images: robot tokens inventoried in
KEY_CUSTODY) · tag-gated publish (`v*`; `workflow_dispatch` is a dry run) · release gate = CI (`workflow_call`) ·
Dependabot (cargo, docker, actions) · images per the IMG lens · secrets never echoed · no real-funds job (the e2e script is
manual and off CI) · test-only modes: none in the binary (the database tests' insecure switch is an environment variable
that production never sets, and the configuration refuses a plaintext URL without it).

### B.RS-1 Build & release

`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and the MSRV job (1.94) run in CI. The image is per the IMG
lens (F22, F23). No crates are published.

### B.SC-1 ID-constant trace

| Location | Network | Value | original-id / published-at | Matches latest |
| --- | --- | --- | --- | --- |
| workspace `methods.json` (both methods) | testnet | package `0x5f67…bc14`, merchant `0x29d6…63f8` | one field for both (F29) | Y (`chain-payments-sui/Published.toml`, version 1; merchant read on-chain 2026-11-17) |
| `crates/chain-sui` tests, `scripts/e2e-testnet.sh` | testnet | `0x5f67…bc14`, TEST merchant `0x30b6…dae8` | both | Y (test-only) |
| `crates/service/tests/api.rs` | testnet | `0x5f67`, `0x30b6` (short, never reaches a chain) | — | n/a |

### B.SC-2 Coupling

| Move item | Service code | Test |
| --- | --- | --- |
| `quote_message` | `QuoteFields::message` | `matches_the_move_package_vectors` |
| `Paid` fields | `check_response` | `recorded_payment_is_confirmed_and_any_difference_is_not` (a real testnet transaction) |
| `pay<T>` arguments (built by the client from this service's quote JSON) | `App::quote` response fields | client audit B.SC-2 |

### B.SC-3 Cross-implementation parity

| Behaviour | Implementation A | Implementation B | Shared vector / test |
| --- | --- | --- | --- |
| Quote message | `chain_payments::quote_message` (Move) | `QuoteFields::message` (Rust) | `tests/vectors.json` = `fixtures/quote-vectors.json` |
| Webhook signature check | `core::webhook::check` | `link-in-bio-service billing::chain_payments::signature_valid` | none shared (each tests its own round trip); suggestion |
| Event-type matching | here (`normalize_move_type`) | the gateways (`consumed_event_type`) | the same core functions |

### B.AUTH-1 Key & credential inventory

| Key / credential | Type | Where held | Who can read it | Rotation · last rotated | Compromise procedure |
| --- | --- | --- | --- | --- | --- |
| `quote.key` | ed25519 seed | Secret, mounted 0440 | api and worker pods (F27) | on suspicion · created 2026-11-16 | new key, `set_quote_key` on every merchant, or `set_paused` first |
| `webhook.key` | ed25519 seed | same | api and worker pods (F27) | on suspicion · 2026-11-16 | rotate; restart merchants (F10); merchants refuse old-key signatures at once |
| Merchant API keys | opaque, SHA-256 at rest | merchant backends | the merchant's namespace | on suspicion · 2026-11-16 | `merchant rotate-key`, or set `disabled` |
| DB passwords | password | Secrets | the pods using them (F26) | on suspicion · 2026-11-16 | `new-service-db-secret.sh --force` |

### B.AUTH-2 Client & authorization inventory

| Relation | Type | Scopes granted | Owner | Last reviewed |
| --- | --- | --- | --- | --- |
| API key → merchant | bearer, merchant API (in-cluster) | create, read, cancel the merchant's own sessions | operator (`merchant add`) | 2026-11-17 |
| Session id → session | capability, public API | read, quote, claim for that session | the merchant, who hands it to the buyer | 2026-11-17 |

No OAuth clients and no identity provider. The write path for merchants is the CLI against the database, operator-only.

### B.AUTH-3 Protocol conformance

| Protocol | Spec followed | Deviations | Test pinning the wire shape |
| --- | --- | --- | --- |
| Quote signature | `chain_payments::quote_message` | none | shared vectors |
| Webhook signature | `t=<unix>,ed25519=<b64 sig of "<t>.<body>">` (Stripe-like, asymmetric) | no merchant id in the body (F16) | `round_trip_and_tampering` |

### B.DB-1 Roles and grants

| Role | Process | Database | Schema | Tables | Limits | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| `chain_payments_migrate` | migrate Job | owner | owner of `cp` | DDL + DML | 2 connections, 60 s statements | provisioner (platform); no role test here |
| `chain_payments_app` | api, worker, merchant-add | CONNECT | USAGE `cp` | SELECT/INSERT/UPDATE/DELETE, no TRUNCATE, no DDL | 18 connections (api pool 4 × ≤ 3 replicas + worker 4 + Job 1 = 17), 10 s statements, 30 s idle-in-transaction | provisioner; **no role test in this repository** (F26) |

### B.DB-2 Schema change process

- A change is a new numbered file in `crates/store/migrations/`, embedded by `sqlx::migrate!` and checksummed. Editing a
  released file is refused at start.
- The `migrate` Job runs as the owner before the workloads roll (`apply.sh`).
- Queries are runtime-checked (`sqlx::query`), so the store tests on the real engine are the compatibility proof.
- 0002 changes a key that only unreleased code used (F1).
- A newer schema than the build is detected by sqlx as an unknown applied version, and `migrate` refuses it.

## Section C — Test-coverage & hermetic/live split

### C.1 Coverage grade — B+ (35/35 on stable against PostgreSQL over TLS)

| Dimension | Assessment |
| --- | --- |
| Happy path | quote (GBP-pegged in the API test, priced via `money`), claim, confirm, webhook queue, expiry, lock |
| Error paths | wrong claim, cancelled session, duplicate payment, settlement race, unknown claim (404), quote cap, disallowed method, bad key (401), validation (422), every TLS downgrade, bad configuration values |
| Boundaries | spread at the limit, too few sources, zero prices, rounding (proptest), oversize identifiers, 4 KiB and 16 KiB bodies (layer only, no test) |
| Security-relevant | the full-type `Paid` match against a recorded real transaction with every single-field difference; shared quote vectors; webhook tampering and age; key hashing; CORS; no cookies |

Not covered by tests:

- the settle path end to end with a mocked chain (only its parts are tested: the store outcomes, `gives_up`, `check_response`);
- timeout and concurrency behaviour;
- webhook delivery against a stub endpoint (backoff, give-up);
- role-forbidden actions (F26).

### C.2 Hermetic vs live

| Path | Hermetic? | Deferred to | Tracking |
| --- | --- | --- | --- |
| Verification of a real transaction | yes (recorded `GetTransaction` response) | live re-check `LIVE_SUI=1 cargo test -p chain-payments-chain-sui live_testnet` | release checklist |
| Full flow with a real payment | no | `scripts/e2e-testnet.sh` (OK 2026-11-16) | before each release |
| Price sources' live formats | recorded 2026-11-16 in `reads_each_sources_live_format` | live quotes on testnet | `ChainPaymentsNoPrice` alert |
| Image, probes, non-root | no | CI `image` job + `smoke.sh` | CI |
| Restore drill of `chain_payments` | no | the platform's restore drills | pre-mainnet (DB-M9) |
| Reconciliation of unsubmitted payments | — | not built | FU-0124 |

## Section D — Deployment-readiness gates

### pre-localnet

- [x] builds; fmt, clippy `-D warnings`, `cargo deny` green; `forbid(unsafe_code)` (F7)
- [x] tests green on the real engine with TLS (35/35); no secrets in source
- [x] no panics on attacker-reachable paths (I19); no string-built SQL with values (I15)
- [x] migrations embedded and checksummed; enumerations check-constrained

### pre-testnet

- [x] timeouts on every outbound call; response bodies bounded; requests bounded (F6)
- [x] full-type event matching; effects status checked; every bound field compared (F12, F4)
- [x] rate limit keyed on the trusted client address (F21); SIGTERM handled (`shutdown_signal`)
- [x] verify-full TLS; credentials only from Secrets; nothing secret in logs (F19)
- [x] readiness fails, liveness stays up, on database loss (F19)
- [x] B.AUTH-1 and B.AUTH-2 inventories complete
- [ ] one role per process, least privilege proven by tests (F26, FU-0126)
- [ ] deployment references the image by digest (F31, FU-0130)
- [x] `SECURITY.md` present and consistent (F8)

### pre-mainnet

- [ ] unsubmitted payments reconciled from the chain (F24, FU-0124)
- [ ] unapplied payments reported to the merchant (F28, OQ1, FU-0127)
- [ ] per-process keys (F27) and roles (F26)
- [ ] package-id split before the first upgrade (F29, FU-0123)
- [ ] negative shared vectors and a fixture drift check (F30, FU-0128)
- [ ] mainnet full node chosen (OQ3) and its egress added
- [ ] database in the backup set with an offsite copy; a dated restore drill (DB-M9)
- [ ] personal-data inventory and deletion path for `payer` and merchant metadata written (DB-M10)
- [ ] external review

## Cross-project themes

- **Supply chain & release integrity.** `Cargo.lock` committed; exact crate pins; `cargo deny`; Actions, bases and tools
  pinned; signed, attested images; Dependabot (F23).
- **Wire-format coupling & conformance vectors.** The quote message is shared with the Move package through identical vector
  files, but there is no drift check or negatives yet (F30). The `Paid` event is pinned by a recorded real transaction. The
  webhook format is shared with Link in Bio, with no shared vector (suggestion).
- **On-chain-truth boundary.** A payment counts only after the chain says so. The kit's "confirmed" comes from this service,
  which read the chain. Prices are an off-chain valuation, recorded with each quote.
- **Deployment readiness.** Section D.
- **Chain-access layering & on-chain ID/ABI coupling.** The service reads the chain only by digest, through the platform's
  shared gRPC core. Ids come from `methods.json`, traced to the Move repo (B.SC-1). The split before an upgrade is F29.
- **Versioning.** Unreleased; the first tag is 0.0.1 and carries this pass's changes.

## Normative requirements (MUST / MUST NOT)

- MUST confirm a payment only from successful effects and a full-type `Paid` event matching every quote field it carries —
  **holds** (F12, F4).
- MUST NOT let one claim of a digest decide another — **holds** (F1).
- MUST NOT reject a payment because of our own node's unavailability — **holds** (F2).
- MUST eventually recognise every on-chain payment to a registry merchant, submitted or not — **does not hold** (F24).
- MUST tell the merchant about every payment it received, including those it cannot sell — **does not hold** (F28, OQ1).
- MUST NOT quote without two agreeing sources — **holds** (F5, F14).
- RS-M1 holds (F7, I19) · RS-M2 n/a (the service verifies no Sui signatures; it signs ed25519 with `ring`) · RS-M3 holds in
  the shared core (fuzzed there) · RS-M4 holds (F6) · RS-M5 holds · RS-M6 holds (single use is SQL row state; the database
  fails closed) · RS-M7 holds (F21) · RS-M8 holds (I20, `shutdown_signal`) · RS-M9 holds for the quote (vectors).
- SC-M1 holds until the first upgrade (F29) · SC-M2 holds · SC-M3 holds · SC-M4 holds (u64 parsed from digits;
  normalised addresses) · SC-M5 holds (a full node per network in the method's own network) · SC-M6 n/a · SC-M7 holds
  (digest-first) · SC-M8/M9 n/a · SC-M10 holds.
- AUTH-M1 n/a (opaque keys) · AUTH-M2 holds for the seeds and keys (mounted files), rotation documented · AUTH-M3 n/a ·
  AUTH-M4 n/a (no IdP) · AUTH-M5 holds (I13) · AUTH-M6/M7/M8/M9 n/a · AUTH-M10 holds (uniform `401`; ingress rate
  limit; no credentials logged) · AUTH-M11 n/a for a challenge protocol; the quote is versioned and domain-separated.
- DB-M1 holds · DB-M2 holds (F1 note) · DB-M3 **does not hold** (F26) · DB-M4 holds · DB-M5 holds (I14) · DB-M6 holds
  (one sale per session, enumerations) · DB-M7 holds · DB-M8 holds · DB-M9 not yet (pre-mainnet) · DB-M10 not yet
  (pre-mainnet).
- IMG-M1…M5 hold (F22) · IMG-M6 **not yet** (F31) · IMG-M7/M8 hold in the workflow (unexercised until the first tag).
- OPS-M1 holds for `e2e-testnet.sh` (F9) · OPS-M2 holds (`set -euo pipefail`, shellcheck in CI) · OPS-M7/M8 hold
  (manual, no CI keys).

## Implementation suggestions (SHOULD / MAY)

- SHOULD read each registry merchant on-chain at start and periodically (paused, quote key equal to ours, minimums below our
  quotes, no unexpected pending recipient), and refuse to quote otherwise. This also serves the Move audit's F5.
- SHOULD add a settle test with a mocked transport (`Sui::with_transport`) behind a small trait in `App`, so the whole
  path, races included, is tested.
- SHOULD add `merchantId` to webhook payloads (F16) and publish a shared webhook vector for merchants.
- SHOULD stub a webhook endpoint in tests (backoff, give-up, no redirect).
- MAY record the price sources' sample timestamps, not only the quote time, in the price record.

## Open questions (`OQ#`)

- **OQ1** — What happens to a payment that cannot be sold (session already paid, cancelled, or expired for good)? Choose: (a)
  a `payment.unapplied` webhook so the merchant refunds or credits; (b) the operator refunds from the recipient; (c) apply
  it as credit to the subscription reference automatically. (F28)
- **OQ2** — Will merchants ever be created by anyone but the operator? If yes, webhook URLs need a private-address refusal
  and a verification step, and merchant creation needs its own role. (F17, F26)
- **OQ3** — Which mainnet full node: the public Mysten endpoint, or a paid or self-run one with an SLA? Settlement liveness
  depends on it (F2).

## Risks (residual)

- **A lying full node:** the service trusts one configured node's `GetTransaction`. A malicious or compromised node could
  report a payment that did not happen. Checking a second node before confirming large amounts would bound it.
- **Price sources:** a coordinated 2 % move of every source, or all three down (no quotes).
- **Keys on the node:** custody of the quote and webhook seeds is the platform's (SOPS, age).
- **Link in Bio's trust-on-first-use webhook key:** fetched in-cluster over plain HTTP from the Service (NetworkPolicies
  restrict the path; pinning `webhook_key` in its config is available).

## Re-verification log

- 2026-11-17 — First pass at `678192f` plus this pass's changes:
  - read every crate, the migrations, the CI, the Dockerfile, the deployment (network policy, ingress, Deployments, HPA,
    merchant-add), the database roles, the alerts and Link in Bio's adapter;
  - 35/35 tests on PostgreSQL over TLS; clippy, fmt and `cargo deny` clean;
  - fixed F1–F11 inline (migration 0002, settlement outcomes, verification fields, give-up rule, configuration bound,
    request layers, lint level, SECURITY.md, e2e preflight, runbook, ADR amendment);
  - deferred F24–F31 to FU-0123–FU-0128 and FU-0130;
  - opened OQ1–OQ3.

## Pre-save consistency checklist (this pass)

- [x] Section A ↔ findings (I6 GAP → F24; I17 GAP → F26/F27)
- [x] Finding header ↔ body
- [x] Template line
- [x] Closing structure in order
- [x] Open questions stay open
- [x] Section D ↔ dispositions
- [x] Executive summary matches the current dispositions
- [x] Counts re-measured (35 tests; `cargo deny` clean)
- [x] Re-verification log entry
