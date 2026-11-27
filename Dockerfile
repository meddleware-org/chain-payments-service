# =============================================================================
# chain-payments-service — one image, one binary: /app/chain-payments <serve|worker|migrate|merchant|keygen>.
# =============================================================================
# Multi-stage build with cargo-chef for dependency-layer caching:
#   chef     — the Rust toolchain plus cargo-chef
#   planner  — computes the dependency recipe from Cargo.toml/lock
#   notices  — cargo-about licence notices of the binary (fails on an unaccepted licence)
#   builder  — compiles the dependencies (cached), then the binary (--locked)
#   runtime  — distroless/cc: glibc + CA certificates; no shell, no package manager
#
# Storage is PostgreSQL over rustls (ring; the database CA is mounted at run time); the full node and price sources are
# reached over HTTPS. Both base images are pinned by digest (multi-arch index); bump tag and digest together.
# =============================================================================

FROM docker.io/library/rust:1-slim@sha256:4df2ae8cfdfebdfc13a65da7f253b73d68983dc0339f2719bc17a279c913b13d AS chef
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /src

# ── Planner: derive the dependency recipe ────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Licence notices (Apache-2.0 §4(a) and the MIT/BSD notice clauses) ────────
FROM chef AS notices
RUN cargo install --locked --version 0.9.2 --features cli cargo-about
COPY . .
RUN mkdir -p /out \
 && cargo about generate --locked --fail -c about.toml --manifest-path crates/cli/Cargo.toml about.hbs \
      > /out/THIRD_PARTY_LICENSES.txt \
 && grep -q 'Apache License' /out/THIRD_PARTY_LICENSES.txt

# ── Builder: compile deps (cached), then the binary ──────────────────────────
FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json -p chain-payments
COPY . .
RUN cargo build --release --locked -p chain-payments \
 && install -D -m 0755 target/release/chain-payments /out/chain-payments

# ── Runtime: minimal distroless image ────────────────────────────────────────
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:29ee70762214fe8190cea04ef1c0a84a8365879e047ce8f911ae5a5ab2355fa2

ARG VERSION=dev
ARG VENDOR="Meddleware"
ARG DESCRIPTION="Chain Payments: exact, quoted crypto payments for merchants (sessions, quotes, on-chain verification, webhooks)."
ARG SOURCE_URL="https://github.com/meddleware-org/chain-payments-service"
ARG DOCUMENTATION_URL="https://github.com/meddleware-org/chain-payments-service#readme"
ARG IMAGE_URL="https://quay.io/meddleware-org/chain-payments-service"

LABEL org.opencontainers.image.title="chain-payments-service" \
      org.opencontainers.image.description="${DESCRIPTION}" \
      org.opencontainers.image.url="${IMAGE_URL}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.documentation="${DOCUMENTATION_URL}" \
      org.opencontainers.image.vendor="${VENDOR}" \
      org.opencontainers.image.licenses="0BSD" \
      org.opencontainers.image.version="${VERSION}"

WORKDIR /app
COPY --from=builder /out/chain-payments /app/
COPY --from=notices /out/ /app/
# The lockfile makes an image scan list the compiled crates (a stripped binary carries none); inert at runtime.
COPY Cargo.lock /app/Cargo.lock
COPY LICENSE /app/LICENSE

# 65532 is distroless's nonroot user.
USER 65532:65532
EXPOSE 8080 8081
ENV PUBLIC_LISTEN_ADDR=0.0.0.0:8080 INTERNAL_LISTEN_ADDR=0.0.0.0:8081

# Every Deployment and Job sets its `args:` (serve, worker, migrate). Keys are files mounted from Secrets
# (QUOTE_KEY_FILE, WEBHOOK_KEY_FILE); no volume is written.
ENTRYPOINT ["/app/chain-payments"]
CMD ["--help"]
