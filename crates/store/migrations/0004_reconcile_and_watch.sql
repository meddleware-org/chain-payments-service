-- Chain Payments schema 4.
-- cp.event_cursors: how far the worker has read each package's `Paid` events (GraphQL cursors), to find payments whose
-- checkout never submitted the transaction (a closed tab, a failed submission). Each found event becomes an ordinary
-- claim and is verified through the full nodes like any other.
-- cp.merchant_watch: each merchant object's on-chain state as the worker last read it. A pending recipient, a recipient
-- other than the expected one, or a quote key other than this service's stops quoting for that merchant (the two-day
-- recipient delay only protects if someone is watching).
CREATE TABLE cp.event_cursors (
  package_id  text PRIMARY KEY,
  cursor      text NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cp.merchant_watch (
  merchant_object       text PRIMARY KEY,
  recipient             text NOT NULL,
  pending_recipient     text,
  quote_key             text NOT NULL,
  paused                boolean NOT NULL,
  recipient_unexpected  boolean NOT NULL,
  quote_key_foreign     boolean NOT NULL,
  checked_at            timestamptz NOT NULL
);
