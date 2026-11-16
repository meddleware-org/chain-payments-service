-- Chain Payments schema 1. Forward-only: a released migration is never edited.
CREATE SCHEMA IF NOT EXISTS cp;

CREATE TABLE cp.merchants (
  id            uuid PRIMARY KEY,
  name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  -- SHA-256 of the merchant's API key; the key itself is never stored.
  api_key_hash  bytea NOT NULL UNIQUE CHECK (length(api_key_hash) = 32),
  webhook_url   text CHECK (webhook_url IS NULL OR webhook_url LIKE 'https://%' OR webhook_url LIKE 'http://%.svc%'),
  methods       text[] NOT NULL DEFAULT '{}',
  disabled      boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cp.sessions (
  id                text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
  merchant_id       uuid NOT NULL REFERENCES cp.merchants (id),
  amount_pence      bigint NOT NULL CHECK (amount_pence > 0),
  description       text NOT NULL CHECK (length(description) BETWEEN 1 AND 120),
  units             bigint NOT NULL CHECK (units BETWEEN 1 AND 120),
  subscription_ref  text NOT NULL DEFAULT '' CHECK (length(subscription_ref) <= 64),
  period_ms         bigint NOT NULL DEFAULT 0 CHECK (period_ms >= 0),
  methods           text[] NOT NULL,
  metadata          jsonb NOT NULL DEFAULT 'null',
  status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'paid', 'expired', 'cancelled')),
  expires_at        timestamptz NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  paid_at           timestamptz
);
CREATE INDEX sessions_open_expiry ON cp.sessions (expires_at) WHERE status = 'open';

-- Every quote ever signed, with the price record it was computed from (the valuation for the accounts).
CREATE TABLE cp.quotes (
  nonce       text PRIMARY KEY CHECK (nonce ~ '^[0-9a-f]{32}$'),
  session_id  text NOT NULL REFERENCES cp.sessions (id),
  method_id   text NOT NULL,
  coin_type   text NOT NULL,
  amount      bigint NOT NULL CHECK (amount > 0),
  expires_ms  bigint NOT NULL,
  signature   text NOT NULL,
  price       jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX quotes_session ON cp.quotes (session_id);

CREATE TABLE cp.payments (
  digest         text PRIMARY KEY,
  session_id     text NOT NULL REFERENCES cp.sessions (id),
  nonce          text NOT NULL REFERENCES cp.quotes (nonce),
  status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'rejected')),
  payer          text,
  paid_until_ms  bigint,
  attempts       integer NOT NULL DEFAULT 0,
  last_error     text,
  next_check_at  timestamptz NOT NULL DEFAULT now(),
  created_at     timestamptz NOT NULL DEFAULT now(),
  confirmed_at   timestamptz
);
-- A session is paid once.
CREATE UNIQUE INDEX payments_one_confirmed ON cp.payments (session_id) WHERE status = 'confirmed';
CREATE INDEX payments_pending ON cp.payments (next_check_at) WHERE status = 'pending';

-- The webhook outbox: written in the same transaction as the state change, delivered at least once by the worker.
CREATE TABLE cp.webhooks (
  id            uuid PRIMARY KEY,
  merchant_id   uuid NOT NULL REFERENCES cp.merchants (id),
  event         text NOT NULL CHECK (event IN ('session.paid', 'session.expired')),
  payload       jsonb NOT NULL,
  attempts      integer NOT NULL DEFAULT 0,
  next_at       timestamptz NOT NULL DEFAULT now(),
  delivered_at  timestamptz,
  last_error    text,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webhooks_due ON cp.webhooks (next_at) WHERE delivered_at IS NULL;
