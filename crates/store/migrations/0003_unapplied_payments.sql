-- Chain Payments schema 3. A transaction that really paid a quote, but for a session that was already paid or cancelled
-- (two tabs, a quote paid after cancelling), was recorded as `rejected` and the merchant was not told: the buyer could
-- be charged twice unnoticed. It is now `unapplied`, and a `payment.unapplied` webhook tells the merchant, who decides:
-- credit it (e.g. as more of what was bought) or refund it by hand from its recipient. Nothing is refunded
-- automatically: an automatic refund would let anyone make the merchant pay network fees by paying stale quotes.
ALTER TABLE cp.payments DROP CONSTRAINT payments_status_check;
ALTER TABLE cp.payments ADD CONSTRAINT payments_status_check
  CHECK (status IN ('pending', 'confirmed', 'rejected', 'unapplied'));
ALTER TABLE cp.webhooks DROP CONSTRAINT webhooks_event_check;
ALTER TABLE cp.webhooks ADD CONSTRAINT webhooks_event_check
  CHECK (event IN ('session.paid', 'session.expired', 'payment.unapplied'));
