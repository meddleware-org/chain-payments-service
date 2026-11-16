#!/usr/bin/env bash
# Live end to end on Sui testnet: merchant API → session → priced quote → a real payment with the Sui CLI → the digest
# submitted → confirmed on-chain → the session paid and its webhook queued.
#
#   bash scripts/test-postgres.sh start && . "$PG_DIR/env.sh"
#   bash scripts/e2e-testnet.sh
#
# Uses chain-payments-sui's THROWAWAY test merchant on testnet, whose quote key is the public TEST key (seed 0x01 * 32),
# and the active `sui client` address (testnet, a little SUI for gas). Spends about one penny's worth of testnet SUI.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${TEST_DATABASE_URL:?start scripts/test-postgres.sh first}"
[[ "$(sui client active-env)" == testnet ]] || { echo "the active sui env must be testnet" >&2; exit 2; }
PKG=0x5f67109c6b436fc0c0415d7f3e63ca10d374d8c4bb5e3b1f087cabb1c785bc14
MERCHANT=0x30b6d544652d35d4a481fa7e45adf8e514b9ae1596377e837b6fdf36d967dae8

work="$(mktemp -d)"
cleanup() { [[ -n "${srv:-}" ]] && kill "$srv" 2> /dev/null; rm -rf "$work"; }
trap cleanup EXIT
python3 -c 'import sys; sys.stdout.buffer.write(bytes([1]) * 32)' > "$work/quote.key"
cargo build -q -p chain-payments
bin=target/debug/chain-payments
"$bin" keygen --out "$work/webhook.key" > /dev/null
cat > "$work/methods.json" <<JSON
{"methods":[{"id":"sui-testnet:SUI","chain":"sui","network":"testnet","coinType":"0x2::sui::SUI","symbol":"SUI","decimals":9,
  "priceSymbol":"SUI","packageId":"$PKG","merchantObject":"$MERCHANT"}]}
JSON
# The throwaway server's own database: the schema goes into `postgres` (the server is discarded afterwards).
export DATABASE_URL="$TEST_DATABASE_URL"
"$bin" migrate > /dev/null
export METHODS_FILE="$work/methods.json" QUOTE_KEY_FILE="$work/quote.key" WEBHOOK_KEY_FILE="$work/webhook.key"
export SUI_GRPC_TESTNET=https://fullnode.testnet.sui.io:443 ALLOWED_ORIGINS=http://127.0.0.1:4300
export PUBLIC_LISTEN_ADDR=127.0.0.1:18080 INTERNAL_LISTEN_ADDR=127.0.0.1:18081
"$bin" merchant add --name "e2e $(date +%s)" --methods sui-testnet:SUI --key-out "$work/api.key" > /dev/null
"$bin" serve > "$work/serve.log" 2>&1 &
srv=$!
for _ in $(seq 1 40); do curl -fs http://127.0.0.1:18080/healthz > /dev/null && break; sleep 0.25; done

key="$(cat "$work/api.key")"
session="$(curl -fsS -X POST http://127.0.0.1:18081/v1/merchant/sessions -H "authorization: Bearer $key" -H 'content-type: application/json' \
  -d '{"amountPence":1,"description":"e2e one penny","subscriptionRef":"e2e-acct","periodMs":2629800000,"metadata":{"test":true}}' | jq -r .id)"
echo "session $session"
quote="$(curl -fsS -X POST "http://127.0.0.1:18080/v1/sessions/$session/quotes" -H 'content-type: application/json' -d '{"method":"sui-testnet:SUI"}')"
echo "quote: $(jq -r .amountText <<< "$quote") for $(jq -r .priceText <<< "$quote")"
args="$(python3 -c '
import json, sys
q = json.load(sys.stdin)
vec = lambda b: "vector[" + ",".join(str(x) for x in b) + "]"
print("\n".join([vec(q["session"].encode()), q["amount"], str(q["units"]), q["periodMs"], vec(q["subscriptionRef"].encode()),
                 q["expiresMs"], vec(q["nonce"].encode()), vec(bytes.fromhex(q["signature"]))]))' <<< "$quote")"
mapfile -t a <<< "$args"
pay_amount=$(( ${a[1]} + 1000 ))
out="$(sui client ptb --gas-budget 50000000 --json --split-coins gas "[$pay_amount]" --assign c \
  --move-call "$PKG::chain_payments::pay" "<0x2::sui::SUI>" "@$MERCHANT" "${a[0]}" "${a[1]}" "${a[2]}" "${a[3]}" "${a[4]}" "${a[5]}" "${a[6]}" "${a[7]}" c.0 @0x6)"
digest="$(jq -r .digest <<< "$out")"
echo "paid: $digest"
status="$(curl -fsS -X POST "http://127.0.0.1:18080/v1/sessions/$session/payments" -H 'content-type: application/json' \
  -d "{\"nonce\":\"$(jq -r .nonce <<< "$quote")\",\"digest\":\"$digest\"}" | jq -r .status)"
for _ in $(seq 1 10); do
  [[ "$status" == confirmed ]] && break
  sleep 2
  status="$(curl -fsS "http://127.0.0.1:18080/v1/sessions/$session/payments/$digest" | jq -r .status)"
done
[[ "$status" == confirmed ]] || { echo "FAIL: payment status $status" >&2; tail -5 "$work/serve.log" >&2; exit 1; }
final="$(curl -fsS "http://127.0.0.1:18081/v1/merchant/sessions/$session" -H "authorization: Bearer $key")"
[[ "$(jq -r .status <<< "$final")" == paid ]] || { echo "FAIL: session not paid" >&2; exit 1; }
echo "paid until: $(jq -r '.payments[0].paidUntilMs' <<< "$final")"
curl -fsS http://127.0.0.1:18081/metrics | grep -E '^chain_payments_(payments_confirmed_total|webhooks_undelivered) '
echo "e2e: OK"
