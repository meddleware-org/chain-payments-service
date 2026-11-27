//! `chain-payments-store`: every SQL statement of Chain Payments. Runtime-checked queries (`sqlx::query`), each covered
//! by the real-PostgreSQL tests in this crate (TLS, `verify-full`, `scripts/test-postgres.sh`).
//!
//! # The schema (`cp`, four forward-only migrations)
//!
//! A released migration is never edited: sqlx records a checksum of each applied file, comments included, and refuses to
//! start when one changes. Each migration explains its own reason in its header comment; this is the picture they make.
//!
//! - `cp.merchants`: who may create sessions. Only the SHA-256 of an API key is stored, never the key.
//! - `cp.sessions`: what a merchant asks to be paid (`open`, `paid`, `expired` or `cancelled`). Checks in the table repeat
//!   the bounds the API enforces (amount, description, units, reference), so a bug in one layer cannot store what the
//!   other refuses.
//! - `cp.quotes`: every quote ever signed, with the price record it was computed from (the valuation for the accounts).
//!   The nonce is the key, and it is the value the on-chain `Paid` event carries.
//! - `cp.payments`: a claim that one transaction paid one quote, keyed by (digest, nonce). Claims are independent: a wrong
//!   claim is rejected on its own and cannot stand in the way of the right one. A unique index lets one claim per session
//!   be confirmed, so a session is paid once; a second real payment is recorded as `unapplied` and the merchant is told.
//! - `cp.webhooks`: the outbox. A row is written in the same transaction as the state change it announces, and the worker
//!   delivers it at least once with backoff, so a crash can neither lose an event nor announce one that did not happen.
//! - `cp.event_cursors` and `cp.merchant_watch`: how far the worker has read each package's events, and each merchant
//!   object's on-chain state as the worker last read it.
//!
//! # Concurrency
//!
//! The API and the worker both settle claims, so the statements that settle take row locks (`FOR UPDATE`) and the
//! outcome is decided inside one transaction; the loser reads the winner's status. Webhook delivery claims rows with
//! `FOR UPDATE SKIP LOCKED` and a lease, so two workers never send the same webhook at once, and the watcher duties run
//! under a session advisory lock so there is one writer.

/// Database connection settings: the URL, verified TLS and the access mode.
pub mod config;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Row, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

pub use sqlx::Error as DbError;

/// The embedded migrations, run in order and recorded once applied.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// SHA-256 of an API key, the only form stored.
pub fn hash_key(key: &str) -> Vec<u8> {
    // A fast hash is right here: the keys are 192 random bits, so there is nothing to brute-force, and every request pays this cost.
    Sha256::digest(key.as_bytes()).to_vec()
}

/// A merchant that uses the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merchant {
    /// The merchant's id.
    pub id: Uuid,
    /// The merchant's name (shown in the operator tools only).
    pub name: String,
    /// Where signed webhooks are sent; none means no webhooks.
    pub webhook_url: Option<String>,
    /// The ids of the payment methods the merchant has enabled.
    pub methods: Vec<String>,
    /// Whether the merchant is disabled: a disabled merchant's key stops working.
    pub disabled: bool,
}

/// A checkout session as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    /// The session id (a random hex string).
    pub id: String,
    /// The merchant it belongs to.
    pub merchant_id: Uuid,
    /// The price in pence (GBP).
    pub amount_pence: i64,
    /// What the buyer is paying for, one line.
    pub description: String,
    /// Units bought (months for a subscription).
    pub units: i64,
    /// The merchant's subscription reference (empty for a one-off payment).
    pub subscription_ref: String,
    /// The period each unit buys, in milliseconds.
    pub period_ms: i64,
    /// The methods the buyer may use (empty: all the merchant enables).
    pub methods: Vec<String>,
    /// The merchant's opaque metadata, returned unchanged in webhooks.
    pub metadata: Value,
    /// `open`, `paid`, `expired` or `cancelled`.
    pub status: String,
    /// When the session stops accepting payment.
    pub expires_at: OffsetDateTime,
    /// When it was paid, if it was.
    pub paid_at: Option<OffsetDateTime>,
}

/// A signed quote: the exact amount a buyer may pay for a session with one method until it expires.
#[derive(Debug, Clone, PartialEq)]
pub struct Quote {
    /// The quote's unique value; it is the key the payment is tied to on chain.
    pub nonce: String,
    /// The session it prices.
    pub session_id: String,
    /// The payment method id.
    pub method_id: String,
    /// The coin type in the canonical long form.
    pub coin_type: String,
    /// The amount in the coin's smallest unit.
    pub amount: i64,
    /// When the quote expires, in epoch milliseconds.
    pub expires_ms: i64,
    /// The service's ed25519 signature over the quote message, base64.
    pub signature: String,
    /// The valuation record: the agreed price and the samples behind it.
    pub price: Value,
}

/// A claim that a transaction paid a quote, and where its verification stands.
#[derive(Debug, Clone, PartialEq)]
pub struct Payment {
    /// The transaction digest.
    pub digest: String,
    /// The session paid.
    pub session_id: String,
    /// The quote's nonce the transaction claims to pay.
    pub nonce: String,
    /// `pending`, `confirmed`, `unapplied` or `rejected`.
    pub status: String,
    /// The paying address, once confirmed.
    pub payer: Option<String>,
    /// The end of the prepaid period the payment bought, once confirmed.
    pub paid_until_ms: Option<i64>,
    /// How many verification attempts have been made.
    pub attempts: i32,
}

/// A signed webhook waiting to be delivered.
#[derive(Debug, Clone, PartialEq)]
pub struct Webhook {
    /// The delivery id.
    pub id: Uuid,
    /// The merchant it goes to.
    pub merchant_id: Uuid,
    /// The event name (`session.paid`, `session.expired`, `payment.unapplied`).
    pub event: String,
    /// The JSON body that is signed and sent.
    pub payload: Value,
    /// How many deliveries have been tried.
    pub attempts: i32,
}

/// What submitting a payment did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submitted {
    /// A new claim was recorded.
    New,
    /// The claim was already recorded; nothing changed.
    AlreadyKnown,
}

/// What confirming a verified payment did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// This claim paid the session; the `session.paid` webhook is queued.
    Confirmed,
    /// The transaction paid the quote, but the session was no longer open (paid by another transaction, or cancelled):
    /// recorded as `unapplied`, and the `payment.unapplied` webhook is queued for the merchant to credit or refund it.
    Unapplied,
    /// Another process settled this claim first; its current status.
    Already(String),
}

/// The most informative status among a session's claims of one digest: confirmed, unapplied, pending, then rejected.
fn best_status(statuses: impl IntoIterator<Item = String>) -> Option<String> {
    // Rank the statuses; the lowest rank is the most informative one.
    statuses.into_iter().min_by_key(|s| match s.as_str() {
        // A confirmed claim beats everything.
        "confirmed" => 0,
        // Paid, but the session was no longer open.
        "unapplied" => 1,
        // Still waiting for the chain.
        "pending" => 2,
        // Rejected (or anything unknown) ranks last.
        _ => 3,
    })
}

/// The database layer: every statement of the service, over a connection pool.
#[derive(Clone)]
pub struct Store {
    /// The pool the statements run on.
    pool: PgPool,
}

/// Read a session from a row of the sessions table.
fn session_from(r: &sqlx::postgres::PgRow) -> Result<Session, DbError> {
    // Every column is read by name, so a reordered SELECT cannot silently swap two fields.
    Ok(Session {
        id: r.try_get("id")?,
        merchant_id: r.try_get("merchant_id")?,
        amount_pence: r.try_get("amount_pence")?,
        description: r.try_get("description")?,
        units: r.try_get("units")?,
        subscription_ref: r.try_get("subscription_ref")?,
        period_ms: r.try_get("period_ms")?,
        methods: r.try_get("methods")?,
        metadata: r.try_get("metadata")?,
        status: r.try_get("status")?,
        expires_at: r.try_get("expires_at")?,
        paid_at: r.try_get("paid_at")?,
    })
}

/// The session columns, as a literal so every query stays a static string.
macro_rules! session_columns {
    () => {
        "id, merchant_id, amount_pence, description, units, subscription_ref, period_ms, methods, metadata, status, \
         expires_at, paid_at"
    };
}

impl Store {
    /// Wrap a pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The pool, for the worker's advisory lock and tests.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply any migration that has not run.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }

    /// Check the database answers (the readiness probe).
    pub async fn ping(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map(|_| ())
    }

    // ── merchants ──────────────────────────────────────────────────────────

    /// Create a merchant. The API key is stored only as its SHA-256 hash.
    pub async fn create_merchant(
        &self,
        name: &str,
        api_key: &str,
        webhook_url: Option<&str>,
        methods: &[String],
    ) -> Result<Uuid, DbError> {
        // A random merchant id; the API key is separate and is not derived from it.
        let id = Uuid::new_v4();
        sqlx::query(
            // The key is stored as its hash only: a database leak does not reveal a usable key.
            "INSERT INTO cp.merchants (id, name, api_key_hash, webhook_url, methods) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(name)
        .bind(hash_key(api_key))
        .bind(webhook_url)
        .bind(methods)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Replace a merchant's API key (stored as its hash); returns false when no merchant has the id.
    pub async fn rotate_merchant_key(&self, id: Uuid, api_key: &str) -> Result<bool, DbError> {
        // Rotation replaces the hash; the old key stops working at once.
        let r = sqlx::query("UPDATE cp.merchants SET api_key_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(hash_key(api_key))
            .execute(&self.pool)
            .await?;
        // Exactly one row means the merchant existed.
        Ok(r.rows_affected() == 1)
    }

    /// Sets (or, with `None`, clears) a merchant's webhook address. The caller validates the URL first
    /// (`worker::webhook_url_allowed`); returns `false` when no merchant has that id. Pending deliveries read the
    /// address when they are sent, so they go to the new one.
    pub async fn set_merchant_webhook(&self, id: Uuid, webhook_url: Option<&str>) -> Result<bool, DbError> {
        // Webhook addresses are read when a delivery is sent, so changing it redirects deliveries still pending.
        let r = sqlx::query("UPDATE cp.merchants SET webhook_url = $2 WHERE id = $1")
            .bind(id)
            .bind(webhook_url)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// The enabled merchant that owns an API key, if any; the key is compared by its hash.
    pub async fn merchant_by_key(&self, api_key: &str) -> Result<Option<Merchant>, DbError> {
        let r = sqlx::query(
            // A disabled merchant's key finds nothing, which the API reports as an unknown key.
            "SELECT id, name, webhook_url, methods, disabled FROM cp.merchants WHERE api_key_hash = $1 AND NOT disabled",
        )
        .bind(hash_key(api_key))
        .fetch_optional(&self.pool)
        .await?;
        r.map(|r| {
            Ok(Merchant {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                webhook_url: r.try_get("webhook_url")?,
                methods: r.try_get("methods")?,
                disabled: r.try_get("disabled")?,
            })
        })
        .transpose()
    }

    /// A merchant by id, enabled or not.
    pub async fn merchant(&self, id: Uuid) -> Result<Option<Merchant>, DbError> {
        // Lookup by id, disabled or not (the webhook worker needs the address either way).
        let r = sqlx::query("SELECT id, name, webhook_url, methods, disabled FROM cp.merchants WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        r.map(|r| {
            Ok(Merchant {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                webhook_url: r.try_get("webhook_url")?,
                methods: r.try_get("methods")?,
                disabled: r.try_get("disabled")?,
            })
        })
        .transpose()
    }

    // ── sessions ───────────────────────────────────────────────────────────

    /// Create a session in the `open` status.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_session(
        &self,
        id: &str,
        merchant_id: Uuid,
        amount_pence: i64,
        description: &str,
        units: i64,
        subscription_ref: &str,
        period_ms: i64,
        methods: &[String],
        metadata: &Value,
        expires_at: OffsetDateTime,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO cp.sessions (id, merchant_id, amount_pence, description, units, subscription_ref, period_ms, \
             methods, metadata, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id)
        .bind(merchant_id)
        .bind(amount_pence)
        .bind(description)
        .bind(units)
        .bind(subscription_ref)
        .bind(period_ms)
        .bind(methods)
        .bind(metadata)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A session by id.
    pub async fn session(&self, id: &str) -> Result<Option<Session>, DbError> {
        let r = sqlx::query(concat!("SELECT ", session_columns!(), " FROM cp.sessions WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(session_from).transpose()
    }

    /// Cancels an open session of this merchant.
    pub async fn cancel_session(&self, merchant_id: Uuid, id: &str) -> Result<bool, DbError> {
        let r = sqlx::query(
            "UPDATE cp.sessions SET status = 'cancelled' WHERE id = $1 AND merchant_id = $2 AND status = 'open'",
        )
        .bind(id)
        .bind(merchant_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Marks open sessions past their expiry as expired and queues a `session.expired` webhook for each. Returns how
    /// many. A session with a pending payment is left open (the watcher settles it first).
    pub async fn expire_sessions(&self, now: OffsetDateTime) -> Result<u64, DbError> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            // One statement expires every due session and returns what the webhooks need, so the state change and its event cannot drift apart.
            "UPDATE cp.sessions s SET status = 'expired' WHERE s.status = 'open' AND s.expires_at <= $1 \
             AND NOT EXISTS (SELECT 1 FROM cp.payments p WHERE p.session_id = s.id AND p.status = 'pending') \
             RETURNING s.id, s.merchant_id, s.metadata",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await?;
        for r in &rows {
            // For each expired session, queue the webhook in the same transaction as the update.
            let id: String = r.try_get("id")?;
            let merchant_id: Uuid = r.try_get("merchant_id")?;
            let metadata: Value = r.try_get("metadata")?;
            // The payload carries the merchant's metadata unchanged, so it can find its own record.
            let payload = serde_json::json!({ "type": "session.expired", "sessionId": id, "metadata": metadata });
            enqueue(&mut tx, merchant_id, "session.expired", &payload).await?;
        }
        tx.commit().await?;
        Ok(rows.len() as u64)
    }

    // ── quotes ─────────────────────────────────────────────────────────────

    /// Store a signed quote.
    pub async fn insert_quote(&self, q: &Quote) -> Result<(), DbError> {
        sqlx::query(
            // The quote is stored with the price record it was computed from: the valuation behind the amount.
            "INSERT INTO cp.quotes (nonce, session_id, method_id, coin_type, amount, expires_ms, signature, price) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&q.nonce)
        .bind(&q.session_id)
        .bind(&q.method_id)
        .bind(&q.coin_type)
        .bind(q.amount)
        .bind(q.expires_ms)
        .bind(&q.signature)
        .bind(&q.price)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// How many quotes a session has (they are capped per session).
    pub async fn count_quotes(&self, session_id: &str) -> Result<i64, DbError> {
        // Counted, not fetched: only the cap check needs it.
        sqlx::query_scalar("SELECT count(*) FROM cp.quotes WHERE session_id = $1")
            .bind(session_id)
            .fetch_one(&self.pool)
            .await
    }

    /// Payments recorded for a session (newest first).
    pub async fn session_payments(&self, session_id: &str) -> Result<Vec<Payment>, DbError> {
        let rows = sqlx::query(
            "SELECT digest, session_id, nonce, status, payer, paid_until_ms, attempts FROM cp.payments \
             WHERE session_id = $1 ORDER BY created_at DESC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(payment_from).collect()
    }

    /// When a claim was first submitted (the watcher gives up on a transaction nobody can find after a while).
    pub async fn payment_age_secs(&self, digest: &str, nonce: &str, now: OffsetDateTime) -> Result<i64, DbError> {
        let created: OffsetDateTime =
            // The age of a claim decides when the watcher stops waiting for a transaction nobody can find.
            sqlx::query_scalar("SELECT created_at FROM cp.payments WHERE digest = $1 AND nonce = $2")
                .bind(digest)
                .bind(nonce)
                .fetch_one(&self.pool)
                .await?;
        Ok((now - created).whole_seconds())
    }

    /// A quote by its nonce.
    pub async fn quote(&self, nonce: &str) -> Result<Option<Quote>, DbError> {
        let r = sqlx::query(
            "SELECT nonce, session_id, method_id, coin_type, amount, expires_ms, signature, price FROM cp.quotes \
             WHERE nonce = $1",
        )
        .bind(nonce)
        .fetch_optional(&self.pool)
        .await?;
        r.map(|r| {
            Ok(Quote {
                nonce: r.try_get("nonce")?,
                session_id: r.try_get("session_id")?,
                method_id: r.try_get("method_id")?,
                coin_type: r.try_get("coin_type")?,
                amount: r.try_get("amount")?,
                expires_ms: r.try_get("expires_ms")?,
                signature: r.try_get("signature")?,
                price: r.try_get("price")?,
            })
        })
        .transpose()
    }

    // ── payments ───────────────────────────────────────────────────────────

    /// Records a claim that a transaction paid a quote (idempotent per digest and quote). Claims of one digest against
    /// different quotes are independent, so a wrong claim cannot stand in the way of the right one.
    pub async fn submit_payment(&self, digest: &str, session_id: &str, nonce: &str) -> Result<Submitted, DbError> {
        let r = sqlx::query(
            // Idempotent: submitting the same claim twice records it once, and the second call is told it already existed.
            "INSERT INTO cp.payments (digest, session_id, nonce) VALUES ($1, $2, $3) ON CONFLICT (digest, nonce) DO NOTHING",
        )
        .bind(digest)
        .bind(session_id)
        .bind(nonce)
        .execute(&self.pool)
        .await?;
        Ok(if r.rows_affected() == 1 { Submitted::New } else { Submitted::AlreadyKnown })
    }

    /// Where the worker has read a package's `Paid` events up to (a GraphQL cursor).
    pub async fn event_cursor(&self, package_id: &str) -> Result<Option<String>, DbError> {
        // The cursor is per package, so adding a network starts from its own beginning.
        sqlx::query_scalar("SELECT cursor FROM cp.event_cursors WHERE package_id = $1")
            .bind(package_id)
            .fetch_optional(&self.pool)
            .await
    }

    /// Move the event cursor for a package forward.
    pub async fn set_event_cursor(&self, package_id: &str, cursor: &str) -> Result<(), DbError> {
        sqlx::query(
            // An upsert: the first read creates the row, later ones move it forward.
            "INSERT INTO cp.event_cursors (package_id, cursor, updated_at) VALUES ($1, $2, now()) \
             ON CONFLICT (package_id) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = now()",
        )
        .bind(package_id)
        .bind(cursor)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A claim for an on-chain payment no checkout submitted: only for a nonce that is one of our quotes, and only once.
    /// It is then settled like any other claim (verified through the full nodes).
    pub async fn claim_found_payment(&self, digest: &str, nonce: &str) -> Result<bool, DbError> {
        let r = sqlx::query(
            // The claim is built from our own quote of that nonce, so an event for a nonce we never signed inserts nothing.
            "INSERT INTO cp.payments (digest, session_id, nonce) SELECT $1, q.session_id, q.nonce FROM cp.quotes q \
             WHERE q.nonce = $2 ON CONFLICT (digest, nonce) DO NOTHING",
        )
        .bind(digest)
        .bind(nonce)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Records what the worker read of a merchant object.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_merchant_watch(
        &self,
        merchant_object: &str,
        recipient: &str,
        pending_recipient: Option<&str>,
        quote_key: &str,
        paused: bool,
        recipient_unexpected: bool,
        quote_key_foreign: bool,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        sqlx::query(
            // One row per merchant object, overwritten at each read; `checked_at` shows how stale it is.
            "INSERT INTO cp.merchant_watch (merchant_object, recipient, pending_recipient, quote_key, paused, \
             recipient_unexpected, quote_key_foreign, checked_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (merchant_object) DO UPDATE SET recipient = EXCLUDED.recipient, \
             pending_recipient = EXCLUDED.pending_recipient, quote_key = EXCLUDED.quote_key, paused = EXCLUDED.paused, \
             recipient_unexpected = EXCLUDED.recipient_unexpected, quote_key_foreign = EXCLUDED.quote_key_foreign, \
             checked_at = EXCLUDED.checked_at",
        )
        .bind(merchant_object)
        .bind(recipient)
        .bind(pending_recipient)
        .bind(quote_key)
        .bind(paused)
        .bind(recipient_unexpected)
        .bind(quote_key_foreign)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Why quoting for a merchant object is held, if it is (a pending or unexpected recipient, a foreign quote key).
    pub async fn merchant_hold(&self, merchant_object: &str) -> Result<Option<&'static str>, DbError> {
        let r = sqlx::query(
            // Only the three conditions that stop quoting are read.
            "SELECT pending_recipient IS NOT NULL AS pending, recipient_unexpected, quote_key_foreign \
             FROM cp.merchant_watch WHERE merchant_object = $1",
        )
        .bind(merchant_object)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = r else { return Ok(None) };
        // Checked in order of seriousness: a foreign quote key, then an unexpected recipient, then a pending change.
        Ok(if r.try_get::<bool, _>("quote_key_foreign")? {
            Some("the merchant's quote key on-chain is not this service's")
        } else if r.try_get::<bool, _>("recipient_unexpected")? {
            Some("the merchant's recipient on-chain is not the expected one")
        } else if r.try_get::<bool, _>("pending")? {
            Some("a change of the merchant's recipient is pending")
        } else {
            None
        })
    }

    /// Every watched merchant: (object, pending recipient, recipient unexpected, quote key foreign, seconds since read).
    pub async fn merchant_watch_flags(&self) -> Result<Vec<(String, bool, bool, bool, i64)>, DbError> {
        let rows = sqlx::query(
            // The age is computed by the database clock, so the worker's clock cannot skew it.
            "SELECT merchant_object, pending_recipient IS NOT NULL AS pending, recipient_unexpected, quote_key_foreign, \
             extract(epoch FROM now() - checked_at)::bigint AS age FROM cp.merchant_watch ORDER BY 1",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("merchant_object")?,
                    r.try_get("pending")?,
                    r.try_get("recipient_unexpected")?,
                    r.try_get("quote_key_foreign")?,
                    r.try_get("age")?,
                ))
            })
            .collect()
    }

    /// How many claims of a session are still waiting for the chain.
    pub async fn pending_claims(&self, session_id: &str) -> Result<i64, DbError> {
        // Pending claims of one session, for the per-session cap.
        sqlx::query_scalar("SELECT count(*) FROM cp.payments WHERE session_id = $1 AND status = 'pending'")
            .bind(session_id)
            .fetch_one(&self.pool)
            .await
    }

    /// Withdraws a claim that is still pending (one beyond the per-session cap).
    pub async fn withdraw_pending_claim(&self, digest: &str, nonce: &str) -> Result<(), DbError> {
        // Only a still-pending claim can be withdrawn: a settled one is a record.
        sqlx::query("DELETE FROM cp.payments WHERE digest = $1 AND nonce = $2 AND status = 'pending'")
            .bind(digest)
            .bind(nonce)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// One claim by transaction digest and quote nonce.
    pub async fn payment(&self, digest: &str, nonce: &str) -> Result<Option<Payment>, DbError> {
        let r = sqlx::query(
            "SELECT digest, session_id, nonce, status, payer, paid_until_ms, attempts FROM cp.payments \
             WHERE digest = $1 AND nonce = $2",
        )
        .bind(digest)
        .bind(nonce)
        .fetch_optional(&self.pool)
        .await?;
        r.map(|r| payment_from(&r)).transpose()
    }

    /// The status of a digest for a session: the best of its claims (what a checkout following its payment sees).
    pub async fn session_payment_status(&self, session_id: &str, digest: &str) -> Result<Option<String>, DbError> {
        let statuses: Vec<String> =
            // Several claims can share one digest; the best of them is what a checkout following the digest sees.
            sqlx::query_scalar("SELECT status FROM cp.payments WHERE session_id = $1 AND digest = $2")
                .bind(session_id)
                .bind(digest)
                .fetch_all(&self.pool)
                .await?;
        Ok(best_status(statuses))
    }

    /// Pending payments due for a check (the watcher), oldest first.
    pub async fn due_payments(&self, now: OffsetDateTime, limit: i64) -> Result<Vec<Payment>, DbError> {
        let rows = sqlx::query(
            "SELECT digest, session_id, nonce, status, payer, paid_until_ms, attempts FROM cp.payments \
             WHERE status = 'pending' AND next_check_at <= $1 ORDER BY next_check_at LIMIT $2",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(payment_from).collect()
    }

    /// Confirms a payment, marks its session paid and queues the `session.paid` webhook, all in one transaction. A
    /// session already paid (by another transaction) or cancelled keeps its state: this payment is recorded as
    /// `unapplied` and the `payment.unapplied` webhook is queued instead, in the same transaction.
    pub async fn confirm_payment(
        &self,
        digest: &str,
        nonce: &str,
        payer: &str,
        paid_until_ms: i64,
        platform_fee: u64,
        now: OffsetDateTime,
    ) -> Result<Settled, DbError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            // Lock the claim and its session until the transaction ends, so the API and the worker cannot settle the same claim twice.
            "SELECT p.session_id, s.merchant_id, s.metadata, s.amount_pence, s.units, s.subscription_ref, q.method_id, \
             q.coin_type, q.amount, q.price FROM cp.payments p JOIN cp.sessions s ON s.id = p.session_id \
             JOIN cp.quotes q ON q.nonce = p.nonce WHERE p.digest = $1 AND p.nonce = $2 AND p.status = 'pending' \
             FOR UPDATE OF p, s",
        )
        .bind(digest)
        .bind(nonce)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            // Nothing to settle: release the transaction before reading the winner's status.
            tx.rollback().await?;
            // Settled by another process (the API's immediate check and the watcher race on every submission).
            let status = self.payment(digest, nonce).await?.map(|p| p.status).unwrap_or_else(|| "rejected".into());
            return Ok(Settled::Already(status));
        };
        let session_id: String = row.try_get("session_id")?;
        let paid = sqlx::query(
            // A session pays once: only an open session (or one that expired while the payment was in flight) becomes paid.
            "UPDATE cp.sessions SET status = 'paid', paid_at = $2 WHERE id = $1 AND status IN ('open', 'expired')",
        )
        .bind(&session_id)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        // Not paid by this claim means the session was already paid or cancelled: the money arrived but nothing was bought.
        let status = if paid { "confirmed" } else { "unapplied" };
        sqlx::query(
            // An unapplied claim records why, so a person can see it in the table.
            "UPDATE cp.payments SET status = $3, payer = $4, paid_until_ms = $5, confirmed_at = $6, \
             last_error = CASE WHEN $3 = 'unapplied' THEN 'paid on-chain, but the session was no longer open' ELSE NULL END \
             WHERE digest = $1 AND nonce = $2",
        )
        .bind(digest)
        .bind(nonce)
        .bind(status)
        .bind(payer)
        .bind(paid_until_ms)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let merchant_id: Uuid = row.try_get("merchant_id")?;
        // The webhook reports the session's status at the time, which tells the merchant why a payment was unapplied.
        let session_status: String = if paid {
            "paid".into()
        } else {
            sqlx::query_scalar("SELECT status FROM cp.sessions WHERE id = $1")
                .bind(&session_id)
                .fetch_one(&mut *tx)
                .await?
        };
        // Two events: the normal one, and the one that asks the merchant to credit or refund.
        let event = if paid { "session.paid" } else { "payment.unapplied" };
        {
            let payload = serde_json::json!({
                "type": event,
                "sessionStatus": session_status,
                "sessionId": session_id,
                "metadata": row.try_get::<Value, _>("metadata")?,
                "amountPence": row.try_get::<i64, _>("amount_pence")?,
                "units": row.try_get::<i64, _>("units")?,
                "subscriptionRef": row.try_get::<String, _>("subscription_ref")?,
                "method": row.try_get::<String, _>("method_id")?,
                "coinType": row.try_get::<String, _>("coin_type")?,
                "amount": row.try_get::<i64, _>("amount")?.to_string(),
                "price": row.try_get::<Value, _>("price")?,
                "digest": digest,
                "payer": payer,
                "paidUntilMs": paid_until_ms,
                // In the coin's smallest unit, out of `amount`: the merchant's recipient received `amount - platformFee`.
                "platformFee": platform_fee.to_string(),
            });
            // The webhook row is written inside the same transaction as the settlement.
            enqueue(&mut tx, merchant_id, event, &payload).await?;
        }
        tx.commit().await?;
        Ok(if paid { Settled::Confirmed } else { Settled::Unapplied })
    }

    /// Records a check that did not confirm: retry later (`retry_at`) or reject for good (`None`).
    pub async fn payment_not_confirmed(
        &self,
        digest: &str,
        nonce: &str,
        error: &str,
        retry_at: Option<OffsetDateTime>,
    ) -> Result<(), DbError> {
        // Retry later (stay pending, with the next check time) or reject for good.
        let (status, next) = match retry_at {
            Some(t) => ("pending", t),
            None => ("rejected", OffsetDateTime::now_utc()),
        };
        sqlx::query(
            // Only a pending claim changes; the attempt count feeds the retry backoff.
            "UPDATE cp.payments SET status = $3, attempts = attempts + 1, last_error = $4, next_check_at = $5 \
             WHERE digest = $1 AND nonce = $2 AND status = 'pending'",
        )
        .bind(digest)
        .bind(nonce)
        .bind(status)
        .bind(error)
        .bind(next)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── webhooks ───────────────────────────────────────────────────────────

    /// Claims up to `limit` due webhooks (skipping rows another worker holds) and moves their next attempt forward by
    /// `lease_secs`, so a crash mid-delivery retries later instead of never.
    pub async fn claim_webhooks(
        &self,
        now: OffsetDateTime,
        limit: i64,
        lease_secs: i64,
    ) -> Result<Vec<Webhook>, DbError> {
        let rows = sqlx::query(
            // The lease: pushing `next_at` forward when claiming means a worker that dies mid-delivery is retried later instead of never.
            // Oldest due first, undelivered only, at most `limit`.
            // Rows another worker holds are skipped, so two workers never take the same webhook.
            "UPDATE cp.webhooks SET next_at = $1 + make_interval(secs => $3), attempts = attempts + 1 WHERE id IN \
             (SELECT id FROM cp.webhooks WHERE delivered_at IS NULL AND next_at <= $1 ORDER BY next_at LIMIT $2 \
             FOR UPDATE SKIP LOCKED) RETURNING id, merchant_id, event, payload, attempts",
        )
        .bind(now)
        .bind(limit)
        .bind(lease_secs as f64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Webhook {
                    id: r.try_get("id")?,
                    merchant_id: r.try_get("merchant_id")?,
                    event: r.try_get("event")?,
                    payload: r.try_get("payload")?,
                    attempts: r.try_get("attempts")?,
                })
            })
            .collect()
    }

    /// Mark a delivery as sent and clear its last error.
    pub async fn webhook_delivered(&self, id: Uuid, now: OffsetDateTime) -> Result<(), DbError> {
        // Delivered rows stay in the table (the outbox is a record), marked and cleared of the last error.
        sqlx::query("UPDATE cp.webhooks SET delivered_at = $2, last_error = NULL WHERE id = $1")
            .bind(id)
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record a failed delivery and when to try again.
    pub async fn webhook_failed(&self, id: Uuid, error: &str, next_at: OffsetDateTime) -> Result<(), DbError> {
        // A failure keeps the reason class and the next attempt time.
        sqlx::query("UPDATE cp.webhooks SET last_error = $2, next_at = $3 WHERE id = $1")
            .bind(id)
            .bind(error)
            .bind(next_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Counts for metrics: open sessions, pending payments, undelivered webhooks.
    pub async fn backlog(&self) -> Result<(i64, i64, i64), DbError> {
        let r = sqlx::query(
            // Three counts in one round trip, served by the partial indexes.
            "SELECT (SELECT count(*) FROM cp.sessions WHERE status = 'open') AS open, \
             (SELECT count(*) FROM cp.payments WHERE status = 'pending') AS pending, \
             (SELECT count(*) FROM cp.webhooks WHERE delivered_at IS NULL) AS undelivered",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((r.try_get("open")?, r.try_get("pending")?, r.try_get("undelivered")?))
    }

    /// Runs `f` while holding the single-writer advisory lock (the watcher); returns `None` when another holds it.
    pub async fn try_watcher_lock(&self) -> Result<Option<sqlx::pool::PoolConnection<Postgres>>, DbError> {
        // The lock belongs to a session, so the connection that holds it is returned and kept for as long as the worker runs.
        let mut conn = self.pool.acquire().await?;
        // A non-blocking advisory lock: another worker holding it makes this call return `None` instead of waiting.
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(7_377_001)").fetch_one(&mut *conn).await?;
        Ok(got.then_some(conn))
    }
}

/// Read a payment claim from a row.
fn payment_from(r: &sqlx::postgres::PgRow) -> Result<Payment, DbError> {
    // Read each column by name, so a reordered SELECT cannot swap two fields.
    Ok(Payment {
        digest: r.try_get("digest")?,
        session_id: r.try_get("session_id")?,
        nonce: r.try_get("nonce")?,
        status: r.try_get("status")?,
        payer: r.try_get("payer")?,
        paid_until_ms: r.try_get("paid_until_ms")?,
        attempts: r.try_get("attempts")?,
    })
}

/// Queue a webhook inside the caller's transaction, so the event and the state change commit together.
async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    merchant_id: Uuid,
    event: &str,
    payload: &Value,
) -> Result<(), DbError> {
    // The outbox row; the caller's transaction decides whether it exists.
    sqlx::query("INSERT INTO cp.webhooks (id, merchant_id, event, payload) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4())
        .bind(merchant_id)
        .bind(event)
        .bind(payload)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Access, DatabaseSettings};

    /// A fresh database per test on the server `scripts/test-postgres.sh` starts. Without TEST_DATABASE_URL the test
    /// returns at once, unless REQUIRE_TEST_DATABASE=1 (CI), which makes a missing server a failure.
    async fn store() -> Option<Store> {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            assert!(std::env::var("REQUIRE_TEST_DATABASE").as_deref() != Ok("1"), "TEST_DATABASE_URL is required");
            eprintln!("SKIPPED: no TEST_DATABASE_URL");
            return None;
        };
        let admin =
            DatabaseSettings::parse(&url, false).expect("verify-full URL").lazy_pool(2, Access::ReadWrite).unwrap();
        // A new database per test, so tests never see each other's rows and can run in parallel.
        let name = format!("cp_test_{}", Uuid::new_v4().simple());
        // The name is generated here from a UUID (hex only): safe to splice.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.unwrap();
        // The test database is reached with the same TLS settings as the admin one.
        let db_url = url.replacen("/postgres?", &format!("/{name}?"), 1);
        let pool = DatabaseSettings::parse(&db_url, false).unwrap().lazy_pool(4, Access::ReadWrite).unwrap();
        let s = Store::new(pool);
        // Every test starts from the real migrations, not a hand-made schema.
        s.migrate().await.unwrap();
        Some(s)
    }

    /// A merchant with an enabled method, an open session and one quote; returns the merchant id, the session id and the quote nonce.
    async fn fixture(s: &Store) -> (Uuid, String, String) {
        let m = s
            .create_merchant("Link in Bio", "key-1", Some("https://example.org/hook"), &["sui-testnet:SUI".into()])
            .await
            .unwrap();
        // A fixed session id (32 hex digits) so the assertions can name it.
        let id = "0123456789abcdef0123456789abcdef".to_string();
        s.create_session(
            &id,
            m,
            300,
            "1 month",
            1,
            "acct",
            2_629_800_000,
            &["sui-testnet:SUI".into()],
            &serde_json::json!({"a": 1}),
            OffsetDateTime::now_utc() + time::Duration::minutes(30),
        )
        .await
        .unwrap();
        // A fixed quote nonce for the same reason.
        let nonce = "fedcba9876543210fedcba9876543210".to_string();
        s.insert_quote(&Quote {
            nonce: nonce.clone(),
            session_id: id.clone(),
            method_id: "sui-testnet:SUI".into(),
            coin_type: "0000000000000000000000000000000000000000000000000000000000000002::sui::SUI".into(),
            amount: 5_542_213_191,
            expires_ms: 1,
            signature: "00".into(),
            price: serde_json::json!({"pricePico": "541300000000"}),
        })
        .await
        .unwrap();
        (m, id, nonce)
    }

    /// Keys are hashed and disabled merchants cannot authenticate.
    #[tokio::test]
    async fn keys_are_hashed_and_disabled_merchants_cannot_authenticate() {
        let Some(s) = store().await else { return };
        let (m, _, _) = fixture(&s).await;
        assert_eq!(s.merchant_by_key("key-1").await.unwrap().unwrap().id, m);
        assert!(s.merchant_by_key("key-2").await.unwrap().is_none());
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT api_key_hash FROM cp.merchants").fetch_one(s.pool()).await.unwrap();
        // The stored value is the hash, never the key itself.
        assert_ne!(stored, b"key-1".to_vec());
        // After rotation the old key stops working at once.
        assert!(s.rotate_merchant_key(m, "key-2").await.unwrap());
        assert!(s.merchant_by_key("key-1").await.unwrap().is_none());
        // Disabling a merchant stops its key without deleting anything.
        sqlx::query("UPDATE cp.merchants SET disabled = true").execute(s.pool()).await.unwrap();
        assert!(s.merchant_by_key("key-2").await.unwrap().is_none());
    }

    /// A merchants webhook address can be changed and cleared.
    #[tokio::test]
    async fn a_merchants_webhook_address_can_be_changed_and_cleared() {
        let Some(s) = store().await else { return };
        let (m, _, _) = fixture(&s).await;
        // An in-cluster address, the form the table accepts for plain http.
        let to = "http://link-in-bio-api.hosting.svc.cluster.local:8081/internal/v1/payments";
        assert!(s.set_merchant_webhook(m, Some(to)).await.unwrap());
        assert_eq!(s.merchant(m).await.unwrap().unwrap().webhook_url.as_deref(), Some(to));
        assert!(s.set_merchant_webhook(m, None).await.unwrap());
        assert_eq!(s.merchant(m).await.unwrap().unwrap().webhook_url, None);
        // An unknown merchant changes nothing and says so.
        assert!(!s.set_merchant_webhook(Uuid::new_v4(), Some(to)).await.unwrap());
        // The table's own rule still refuses a plain-http address outside the cluster.
        assert!(s.set_merchant_webhook(m, Some("http://example.org/hook")).await.is_err());
    }

    /// A second quote of the fixture's session (what anyone who knows the session id can ask for).
    async fn second_quote(s: &Store, session: &str) -> String {
        let nonce = "00112233445566778899aabbccddeeff".to_string();
        s.insert_quote(&Quote {
            nonce: nonce.clone(),
            session_id: session.to_string(),
            method_id: "sui-testnet:SUI".into(),
            coin_type: "0000000000000000000000000000000000000000000000000000000000000002::sui::SUI".into(),
            amount: 5_542_213_191,
            expires_ms: 1,
            signature: "00".into(),
            price: serde_json::json!({"pricePico": "541300000000"}),
        })
        .await
        .unwrap();
        nonce
    }

    /// A confirmed payment pays the session once and queues one webhook.
    #[tokio::test]
    async fn a_confirmed_payment_pays_the_session_once_and_queues_one_webhook() {
        let Some(s) = store().await else { return };
        let (_, session, nonce) = fixture(&s).await;
        assert_eq!(s.submit_payment("D1", &session, &nonce).await.unwrap(), Submitted::New);
        // Submitting the same claim again is idempotent.
        assert_eq!(s.submit_payment("D1", &session, &nonce).await.unwrap(), Submitted::AlreadyKnown);
        // A different transaction against the same quote is a separate claim.
        assert_eq!(s.submit_payment("D2", &session, &nonce).await.unwrap(), Submitted::New);
        assert_eq!(
            s.confirm_payment("D1", &nonce, "0xpayer", 42, 7, OffsetDateTime::now_utc()).await.unwrap(),
            Settled::Confirmed
        );
        assert_eq!(
            s.confirm_payment("D1", &nonce, "0xpayer", 42, 7, OffsetDateTime::now_utc()).await.unwrap(),
            Settled::Already("confirmed".into()),
            "a second settlement of the same claim reports the first one's outcome, not a rejection"
        );
        assert_eq!(
            s.confirm_payment("D2", &nonce, "0xother", 43, 7, OffsetDateTime::now_utc()).await.unwrap(),
            Settled::Unapplied,
            "a second payment is not a second sale"
        );
        assert_eq!(s.payment("D2", &nonce).await.unwrap().unwrap().status, "unapplied");
        assert_eq!(s.session(&session).await.unwrap().unwrap().status, "paid");
        // Two webhooks are queued: the sale, and the notice about the second payment.
        let mut hooks = s.claim_webhooks(OffsetDateTime::now_utc(), 10, 60).await.unwrap();
        assert_eq!(hooks.len(), 2, "the sale, and the merchant is told about the second payment");
        // The order of claimed rows is not part of the contract, so sort by event.
        hooks.sort_by_key(|h| h.event.clone());
        assert_eq!(hooks[0].event, "payment.unapplied");
        assert_eq!(
            (hooks[0].payload["payer"].as_str(), hooks[0].payload["digest"].as_str()),
            (Some("0xother"), Some("D2"))
        );
        assert_eq!(hooks[0].payload["sessionStatus"], "paid");
        s.webhook_delivered(hooks[0].id, OffsetDateTime::now_utc()).await.unwrap();
        // Continue with the sale webhook.
        hooks.remove(0);
        assert_eq!(hooks[0].payload["paidUntilMs"], 42);
        assert_eq!(hooks[0].payload["platformFee"], "7");
        assert_eq!(hooks[0].payload["metadata"]["a"], 1);
        // A claimed webhook is leased: nobody else is handed it while the lease lasts.
        assert!(s.claim_webhooks(OffsetDateTime::now_utc(), 10, 60).await.unwrap().is_empty(), "leased");
        s.webhook_delivered(hooks[0].id, OffsetDateTime::now_utc()).await.unwrap();
        assert!(
            s.claim_webhooks(OffsetDateTime::now_utc() + time::Duration::minutes(5), 10, 60).await.unwrap().is_empty()
        );
    }

    /// A wrong claim of a digest cannot block the right one.
    #[tokio::test]
    async fn a_wrong_claim_of_a_digest_cannot_block_the_right_one() {
        let Some(s) = store().await else { return };
        let (_, session, nonce) = fixture(&s).await;
        let other = second_quote(&s, &session).await;
        // Someone who read the Paid event submits its digest against another quote first; the chain check rejects it.
        assert_eq!(s.submit_payment("D1", &session, &other).await.unwrap(), Submitted::New);
        s.payment_not_confirmed("D1", &other, "the transaction did not pay this quote", None).await.unwrap();
        assert_eq!(s.session_payment_status(&session, "D1").await.unwrap().as_deref(), Some("rejected"));
        // The payer's own claim is a new record and is confirmed.
        assert_eq!(s.submit_payment("D1", &session, &nonce).await.unwrap(), Submitted::New);
        assert_eq!(
            s.confirm_payment("D1", &nonce, "0xpayer", 42, 7, OffsetDateTime::now_utc()).await.unwrap(),
            Settled::Confirmed
        );
        assert_eq!(s.session_payment_status(&session, "D1").await.unwrap().as_deref(), Some("confirmed"));
        assert_eq!(s.session(&session).await.unwrap().unwrap().status, "paid");
        assert!(s.session_payment_status(&session, "D9").await.unwrap().is_none());
    }

    /// A payment for a cancelled session is unapplied and the merchant is told.
    #[tokio::test]
    async fn a_payment_for_a_cancelled_session_is_unapplied_and_the_merchant_is_told() {
        let Some(s) = store().await else { return };
        let (m, session, nonce) = fixture(&s).await;
        assert!(s.cancel_session(m, &session).await.unwrap());
        s.submit_payment("D1", &session, &nonce).await.unwrap();
        assert_eq!(
            s.confirm_payment("D1", &nonce, "0xpayer", 42, 7, OffsetDateTime::now_utc()).await.unwrap(),
            Settled::Unapplied
        );
        let p = s.payment("D1", &nonce).await.unwrap().unwrap();
        assert_eq!((p.status.as_str(), p.payer.as_deref()), ("unapplied", Some("0xpayer")));
        assert_eq!(s.session(&session).await.unwrap().unwrap().status, "cancelled", "the session is not sold");
        let hooks = s.claim_webhooks(OffsetDateTime::now_utc(), 10, 60).await.unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(
            (hooks[0].event.as_str(), hooks[0].payload["sessionStatus"].as_str()),
            ("payment.unapplied", Some("cancelled"))
        );
        assert_eq!(s.session_payment_status(&session, "D1").await.unwrap().as_deref(), Some("unapplied"));
    }

    /// Best status prefers confirmed then pending.
    #[test]
    fn best_status_prefers_confirmed_then_pending() {
        let v = |x: &[&str]| best_status(x.iter().map(|s| s.to_string()));
        assert_eq!(v(&["rejected", "confirmed", "pending"]).as_deref(), Some("confirmed"));
        assert_eq!(v(&["pending", "unapplied", "rejected"]).as_deref(), Some("unapplied"));
        assert_eq!(v(&["rejected", "pending"]).as_deref(), Some("pending"));
        assert_eq!(v(&["rejected"]).as_deref(), Some("rejected"));
        assert_eq!(v(&[]), None);
    }

    /// Expiry waits for pending payments and queues a webhook.
    #[tokio::test]
    async fn expiry_waits_for_pending_payments_and_queues_a_webhook() {
        let Some(s) = store().await else { return };
        let (_, session, nonce) = fixture(&s).await;
        s.submit_payment("D1", &session, &nonce).await.unwrap();
        let later = OffsetDateTime::now_utc() + time::Duration::hours(1);
        assert_eq!(s.expire_sessions(later).await.unwrap(), 0, "a pending payment holds the session open");
        s.payment_not_confirmed("D1", &nonce, "the transaction failed", None).await.unwrap();
        assert_eq!(s.expire_sessions(later).await.unwrap(), 1);
        assert_eq!(s.session(&session).await.unwrap().unwrap().status, "expired");
        let hooks = s.claim_webhooks(later, 10, 60).await.unwrap();
        assert_eq!(hooks[0].event, "session.expired");
    }

    /// Due payments and the watcher lock.
    #[tokio::test]
    async fn due_payments_and_the_watcher_lock() {
        let Some(s) = store().await else { return };
        let (_, session, nonce) = fixture(&s).await;
        s.submit_payment("D1", &session, &nonce).await.unwrap();
        assert_eq!(s.due_payments(OffsetDateTime::now_utc() + time::Duration::seconds(1), 10).await.unwrap().len(), 1);
        s.payment_not_confirmed(
            "D1",
            &nonce,
            "not found yet",
            Some(OffsetDateTime::now_utc() + time::Duration::minutes(1)),
        )
        .await
        .unwrap();
        assert!(s.due_payments(OffsetDateTime::now_utc(), 10).await.unwrap().is_empty());
        let first = s.try_watcher_lock().await.unwrap();
        assert!(first.is_some());
        assert!(s.try_watcher_lock().await.unwrap().is_none(), "one writer");
        assert_eq!(s.backlog().await.unwrap(), (1, 1, 0));
    }
}
