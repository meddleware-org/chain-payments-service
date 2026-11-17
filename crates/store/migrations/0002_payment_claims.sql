-- Chain Payments schema 2. A payment record is a CLAIM that one transaction paid one quote: (digest, nonce), not the
-- digest alone. With the digest as the key, whoever submitted a digest first decided which quote it was checked against,
-- so anyone who read a `Paid` event (its session id and nonce are public on-chain) could submit the digest against
-- another quote of the same session, have it rejected, and leave the real payment unrecognised. Claims are now
-- independent: a wrong one is rejected on its own, the right one is still confirmed. One transaction may also pay
-- several quotes. Released together with 0001 (no release ran 0001 alone), so no running process uses the old key.
ALTER TABLE cp.payments DROP CONSTRAINT payments_pkey;
ALTER TABLE cp.payments ADD PRIMARY KEY (digest, nonce);
CREATE INDEX payments_session ON cp.payments (session_id);
