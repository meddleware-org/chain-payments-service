#!/usr/bin/env bash
# Container smoke test: migrate, a merchant, `serve` and `worker`, each as its own read-only, non-root container with every
# capability dropped, against the throwaway TLS PostgreSQL (scripts/test-postgres.sh, started here).
#
#   bash scripts/smoke.sh <image>        # DOCKER=podman for rootless podman
set -euo pipefail
image="${1:?usage: smoke.sh <image>}"
docker="${DOCKER:-docker}"
here="$(cd "$(dirname "$0")/.." && pwd)"
export PG_DIR="${PG_DIR:-${TMPDIR:-/tmp}/chain-payments-smoke-pg}" PG_NAME=chain-payments-smoke-pg PG_PORT=55434 DOCKER="$docker"
work="$(mktemp -d)"
# cleanup: remove the containers, stop the database and delete the work directory; it runs on every exit path (trap below).
cleanup() {
  "$docker" rm -f cp-smoke-serve cp-smoke-worker > /dev/null 2>&1 || true
  bash "$here/scripts/test-postgres.sh" stop
  rm -rf "$work"
}
trap cleanup EXIT
# fail <message>: say what failed, show the tail of the server log and stop the run with status 1.
fail() { echo "smoke: FAIL: $*" >&2; "$docker" logs cp-smoke-serve 2>&1 | tail -5 >&2 || true; exit 1; }

bash "$here/scripts/test-postgres.sh" start > /dev/null
# shellcheck source=/dev/null
. "$PG_DIR/env.sh"
# Inside the containers the CA is mounted at /certs, so the URL points at that path.
url="${TEST_DATABASE_URL/sslrootcert=*/sslrootcert=/certs/ca.crt}"
# Throwaway seeds for the quote and webhook keys: never a real key.
python3 -c 'import sys; sys.stdout.buffer.write(bytes([3]) * 32)' > "$work/quote.key"
python3 -c 'import sys; sys.stdout.buffer.write(bytes([4]) * 32)' > "$work/webhook.key"
cp "$here/examples/methods.json" "$work/methods.json"
# The container runs as a non-root user, so the mounted files must be world-readable.
chmod 0755 "$work" && chmod 0644 "$work"/*

# <name|--rm> <args...>
run() {
  # The first argument is the docker mode (`--rm`, or `-d --name …`); the rest go to the binary.
  local mode="$1"; shift
  "$docker" run $mode --read-only --cap-drop ALL --security-opt no-new-privileges --network host \
    -v "$PG_DIR/certs:/certs:ro" -v "$work:/cfg:ro" -e DATABASE_URL="$url" \
    -e METHODS_FILE=/cfg/methods.json -e QUOTE_KEY_FILE=/cfg/quote.key -e WEBHOOK_KEY_FILE=/cfg/webhook.key \
    -e SUI_GRPC_TESTNET=https://fullnode.testnet.sui.io:443 -e ALLOWED_ORIGINS=https://app.example.org \
    -e PUBLIC_LISTEN_ADDR=127.0.0.1:18180 -e INTERNAL_LISTEN_ADDR=127.0.0.1:18181 \
    -e WORKER_LISTEN_ADDR=127.0.0.1:18182 "$image" "$@"
}

# The image must declare the non-root user the cluster expects.
[ "$("$docker" image inspect --format '{{.Config.User}}' "$image")" = "65532:65532" ] || fail "image user"
# The migration job: it must report the schema up to date.
run --rm migrate | grep -q "schema up to date" || fail "migrate"
# Both long-running roles start as separate containers, as they do in the cluster.
run "-d --name cp-smoke-serve" serve > /dev/null
run "-d --name cp-smoke-worker" worker > /dev/null
# Wait up to ten seconds for readiness.
for _ in $(seq 1 40); do curl -fs http://127.0.0.1:18180/readyz > /dev/null 2>&1 && break; sleep 0.25; done
curl -fs http://127.0.0.1:18180/readyz > /dev/null || fail "readyz"
curl -fs http://127.0.0.1:18180/v1/webhook-key | grep -q '"algorithm":"ed25519"' || fail "webhook key"
# The merchant API refuses a request with no key.
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18181/v1/merchant/sessions -H 'content-type: application/json' -d '{}')" = 401 ] || fail "merchant API without a key"
# A preflight from an origin that is not allowed is refused.
[ "$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS -H 'origin: https://evil.example' http://127.0.0.1:18180/v1/webhook-key)" = 403 ] || fail "CORS"
curl -fs http://127.0.0.1:18181/metrics | grep -q '^chain_payments_sessions_open 0' || fail "metrics"
for _ in $(seq 1 20); do "$docker" logs cp-smoke-worker 2>&1 | grep -q 'worker running' && break; sleep 0.5; done
"$docker" logs cp-smoke-worker 2>&1 | grep -q 'worker running' || fail "worker did not start"
curl -fs http://127.0.0.1:18182/metrics | grep -q '^chain_payments_webhooks_delivered_total 0' || fail "worker metrics"
echo "smoke: OK (${image})"
