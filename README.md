# chain-payments-service

A self-hosted payment provider for crypto: merchants create checkout sessions priced in pounds, buyers pay an **exact**
amount in a coin from their own wallet, and the merchant gets a signed webhook once the payment is final on-chain.

- **Exact price, no escrow.** The service signs a short-lived quote (ed25519) for an exact coin amount; the
  [`chain_payments`](https://github.com/meddleware-org/chain-payments-sui) Move package takes exactly that amount and
  returns the change in the same transaction.
- **Honest prices.** The quote uses the median of free public sources (Kraken, Coinbase, CoinGecko) and refuses to quote
  when they disagree; the price record is kept with every quote.
- **Prepaid periods.** A session may extend a subscription reference by `units × periodMs` on-chain (`paid_until`).
- **Merchant-friendly.** One API key per merchant, sessions over a small REST API, asymmetric webhook signatures (no
  shared secret), an outbox with retries.
- **Multi-chain by design.** Methods come from a registry; Sui (SUI, USDC) first.

## API

Public (checkout; port 8080):

| Method | Path | |
| --- | --- | --- |
| GET | `/v1/sessions/{id}` | amount, description, methods (no merchant metadata) |
| POST | `/v1/sessions/{id}/quotes` | `{"method": "sui-testnet:SUI"}` → the signed quote with the exact amount |
| POST | `/v1/sessions/{id}/payments` | `{"nonce", "digest"}` → `pending` / `confirmed` / `rejected` / `unapplied` |
| GET | `/v1/sessions/{id}/payments/{digest}` | status |
| GET | `/v1/webhook-key` | the webhook public key |

Merchant (port 8081, `Authorization: Bearer <key>`): `POST /v1/merchant/sessions`, `GET /v1/merchant/sessions/{id}`,
`POST /v1/merchant/sessions/{id}/cancel`; `GET /metrics`.

Webhooks: `POST` to the merchant's URL with `chain-payments-signature: t=<unix>,ed25519=<base64 of "<t>.<body>">` and
`chain-payments-event-id`; events `session.paid` (digest, payer, coin amount, price record, `paidUntilMs`),
`session.expired`, and `payment.unapplied` (the same fields and `sessionStatus`): a transaction paid a quote of a session
that was already paid or cancelled. The coins are the merchant's; the merchant credits the buyer or refunds them by hand.
Nothing is refunded automatically, so paying stale quotes cannot make a merchant spend network fees.

Full nodes: `SUI_GRPC_<NETWORK>` is one URL or a comma-separated list on different hosts. With several, a payment counts
only when every node reports it the same way; mainnet requires two, from different operators.

## Running

```bash
chain-payments keygen --out quote.key       # prints the public key for the on-chain merchant
chain-payments keygen --out webhook.key
chain-payments migrate
chain-payments merchant add --name "Shop" --methods sui-testnet:SUI --webhook-url https://shop.example/hooks --key-out shop.key
# or, with a key generated elsewhere (a Secret both sides mount; re-running changes nothing):
chain-payments merchant add --name "Shop" --methods sui-testnet:SUI --key-file /run/secrets/shop.key
METHODS_FILE=methods.json QUOTE_KEY_FILE=quote.key WEBHOOK_KEY_FILE=webhook.key SUI_GRPC_TESTNET=https://fullnode.testnet.sui.io:443 \
  ALLOWED_ORIGINS=https://shop.example DATABASE_URL='postgres://…?sslmode=verify-full&sslrootcert=ca.crt' chain-payments serve
chain-payments worker   # same environment; serves /metrics and /healthz on WORKER_LISTEN_ADDR (0.0.0.0:8081)
```

Image: `quay.io/meddleware-org/chain-payments-service` (multi-arch, cosign-signed by this repository's
`docker-publish.yml`, with SBOMs and provenance). Licence: [0BSD](LICENSE).
