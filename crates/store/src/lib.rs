//! `chain-payments-store`: every SQL statement of Chain Payments. Runtime-checked queries (`sqlx::query`), each covered
//! by the real-PostgreSQL tests in this crate (TLS, `verify-full`, `scripts/test-postgres.sh`).

pub mod config;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub use sqlx::Error as DbError;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// SHA-256 of an API key, the only form stored.
pub fn hash_key(key: &str) -> Vec<u8> {
    Sha256::digest(key.as_bytes()).to_vec()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merchant {
    pub id: Uuid,
    pub name: String,
    pub webhook_url: Option<String>,
    pub methods: Vec<String>,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub id: String,
    pub merchant_id: Uuid,
    pub amount_pence: i64,
    pub description: String,
    pub units: i64,
    pub subscription_ref: String,
    pub period_ms: i64,
    pub methods: Vec<String>,
    pub metadata: Value,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub paid_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Quote {
    pub nonce: String,
    pub session_id: String,
    pub method_id: String,
    pub coin_type: String,
    pub amount: i64,
    pub expires_ms: i64,
    pub signature: String,
    pub price: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Payment {
    pub digest: String,
    pub session_id: String,
    pub nonce: String,
    pub status: String,
    pub payer: Option<String>,
    pub paid_until_ms: Option<i64>,
    pub attempts: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Webhook {
    pub id: Uuid,
    pub merchant_id: Uuid,
    pub event: String,
    pub payload: Value,
    pub attempts: i32,
}

/// What submitting a payment did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submitted {
    New,
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
    statuses.into_iter().min_by_key(|s| match s.as_str() {
        "confirmed" => 0,
        "unapplied" => 1,
        "pending" => 2,
        _ => 3,
    })
}

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

fn session_from(r: &sqlx::postgres::PgRow) -> Result<Session, DbError> {
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
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }

    pub async fn ping(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map(|_| ())
    }

    // ── merchants ──────────────────────────────────────────────────────────

    pub async fn create_merchant(
        &self,
        name: &str,
        api_key: &str,
        webhook_url: Option<&str>,
        methods: &[String],
    ) -> Result<Uuid, DbError> {
        let id = Uuid::new_v4();
        sqlx::query(
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

    pub async fn rotate_merchant_key(&self, id: Uuid, api_key: &str) -> Result<bool, DbError> {
        let r = sqlx::query("UPDATE cp.merchants SET api_key_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(hash_key(api_key))
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn merchant_by_key(&self, api_key: &str) -> Result<Option<Merchant>, DbError> {
        let r = sqlx::query(
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

    pub async fn merchant(&self, id: Uuid) -> Result<Option<Merchant>, DbError> {
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
        expires_at: DateTime<Utc>,
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
    pub async fn expire_sessions(&self, now: DateTime<Utc>) -> Result<u64, DbError> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "UPDATE cp.sessions s SET status = 'expired' WHERE s.status = 'open' AND s.expires_at <= $1 \
             AND NOT EXISTS (SELECT 1 FROM cp.payments p WHERE p.session_id = s.id AND p.status = 'pending') \
             RETURNING s.id, s.merchant_id, s.metadata",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await?;
        for r in &rows {
            let id: String = r.try_get("id")?;
            let merchant_id: Uuid = r.try_get("merchant_id")?;
            let metadata: Value = r.try_get("metadata")?;
            let payload = serde_json::json!({ "type": "session.expired", "sessionId": id, "metadata": metadata });
            enqueue(&mut tx, merchant_id, "session.expired", &payload).await?;
        }
        tx.commit().await?;
        Ok(rows.len() as u64)
    }

    // ── quotes ─────────────────────────────────────────────────────────────

    pub async fn insert_quote(&self, q: &Quote) -> Result<(), DbError> {
        sqlx::query(
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

    pub async fn count_quotes(&self, session_id: &str) -> Result<i64, DbError> {
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
    pub async fn payment_age_secs(&self, digest: &str, nonce: &str, now: DateTime<Utc>) -> Result<i64, DbError> {
        let created: DateTime<Utc> =
            sqlx::query_scalar("SELECT created_at FROM cp.payments WHERE digest = $1 AND nonce = $2")
                .bind(digest)
                .bind(nonce)
                .fetch_one(&self.pool)
                .await?;
        Ok((now - created).num_seconds())
    }

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
            "INSERT INTO cp.payments (digest, session_id, nonce) VALUES ($1, $2, $3) ON CONFLICT (digest, nonce) DO NOTHING",
        )
        .bind(digest)
        .bind(session_id)
        .bind(nonce)
        .execute(&self.pool)
        .await?;
        Ok(if r.rows_affected() == 1 { Submitted::New } else { Submitted::AlreadyKnown })
    }

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
            sqlx::query_scalar("SELECT status FROM cp.payments WHERE session_id = $1 AND digest = $2")
                .bind(session_id)
                .bind(digest)
                .fetch_all(&self.pool)
                .await?;
        Ok(best_status(statuses))
    }

    /// Pending payments due for a check (the watcher), oldest first.
    pub async fn due_payments(&self, now: DateTime<Utc>, limit: i64) -> Result<Vec<Payment>, DbError> {
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
        now: DateTime<Utc>,
    ) -> Result<Settled, DbError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
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
            tx.rollback().await?;
            // Settled by another process (the API's immediate check and the watcher race on every submission).
            let status = self.payment(digest, nonce).await?.map(|p| p.status).unwrap_or_else(|| "rejected".into());
            return Ok(Settled::Already(status));
        };
        let session_id: String = row.try_get("session_id")?;
        let paid = sqlx::query(
            "UPDATE cp.sessions SET status = 'paid', paid_at = $2 WHERE id = $1 AND status IN ('open', 'expired')",
        )
        .bind(&session_id)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        let status = if paid { "confirmed" } else { "unapplied" };
        sqlx::query(
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
        let session_status: String = if paid {
            "paid".into()
        } else {
            sqlx::query_scalar("SELECT status FROM cp.sessions WHERE id = $1")
                .bind(&session_id)
                .fetch_one(&mut *tx)
                .await?
        };
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
        retry_at: Option<DateTime<Utc>>,
    ) -> Result<(), DbError> {
        let (status, next) = match retry_at {
            Some(t) => ("pending", t),
            None => ("rejected", Utc::now()),
        };
        sqlx::query(
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
        now: DateTime<Utc>,
        limit: i64,
        lease_secs: i64,
    ) -> Result<Vec<Webhook>, DbError> {
        let rows = sqlx::query(
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

    pub async fn webhook_delivered(&self, id: Uuid, now: DateTime<Utc>) -> Result<(), DbError> {
        sqlx::query("UPDATE cp.webhooks SET delivered_at = $2, last_error = NULL WHERE id = $1")
            .bind(id)
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn webhook_failed(&self, id: Uuid, error: &str, next_at: DateTime<Utc>) -> Result<(), DbError> {
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
        let mut conn = self.pool.acquire().await?;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(7_377_001)").fetch_one(&mut *conn).await?;
        Ok(got.then_some(conn))
    }
}

fn payment_from(r: &sqlx::postgres::PgRow) -> Result<Payment, DbError> {
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

async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    merchant_id: Uuid,
    event: &str,
    payload: &Value,
) -> Result<(), DbError> {
    sqlx::query("INSERT INTO cp.webhooks (id, merchant_id, event, payload) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4())
        .bind(merchant_id)
        .bind(event)
        .bind(payload)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

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
        let name = format!("cp_test_{}", Uuid::new_v4().simple());
        // The name is generated here from a UUID (hex only): safe to splice.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.unwrap();
        let db_url = url.replacen("/postgres?", &format!("/{name}?"), 1);
        let pool = DatabaseSettings::parse(&db_url, false).unwrap().lazy_pool(4, Access::ReadWrite).unwrap();
        let s = Store::new(pool);
        s.migrate().await.unwrap();
        Some(s)
    }

    async fn fixture(s: &Store) -> (Uuid, String, String) {
        let m = s
            .create_merchant("Link in Bio", "key-1", Some("https://example.org/hook"), &["sui-testnet:SUI".into()])
            .await
            .unwrap();
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
            Utc::now() + chrono::Duration::minutes(30),
        )
        .await
        .unwrap();
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

    #[tokio::test]
    async fn keys_are_hashed_and_disabled_merchants_cannot_authenticate() {
        let Some(s) = store().await else { return };
        let (m, _, _) = fixture(&s).await;
        assert_eq!(s.merchant_by_key("key-1").await.unwrap().unwrap().id, m);
        assert!(s.merchant_by_key("key-2").await.unwrap().is_none());
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT api_key_hash FROM cp.merchants").fetch_one(s.pool()).await.unwrap();
        assert_ne!(stored, b"key-1".to_vec());
        assert!(s.rotate_merchant_key(m, "key-2").await.unwrap());
        assert!(s.merchant_by_key("key-1").await.unwrap().is_none());
        sqlx::query("UPDATE cp.merchants SET disabled = true").execute(s.pool()).await.unwrap();
        assert!(s.merchant_by_key("key-2").await.unwrap().is_none());
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

    #[tokio::test]
    async fn a_confirmed_payment_pays_the_session_once_and_queues_one_webhook() {
        let Some(s) = store().await else { return };
        let (_, session, nonce) = fixture(&s).await;
        assert_eq!(s.submit_payment("D1", &session, &nonce).await.unwrap(), Submitted::New);
        assert_eq!(s.submit_payment("D1", &session, &nonce).await.unwrap(), Submitted::AlreadyKnown);
        assert_eq!(s.submit_payment("D2", &session, &nonce).await.unwrap(), Submitted::New);
        assert_eq!(s.confirm_payment("D1", &nonce, "0xpayer", 42, 7, Utc::now()).await.unwrap(), Settled::Confirmed);
        assert_eq!(
            s.confirm_payment("D1", &nonce, "0xpayer", 42, 7, Utc::now()).await.unwrap(),
            Settled::Already("confirmed".into()),
            "a second settlement of the same claim reports the first one's outcome, not a rejection"
        );
        assert_eq!(
            s.confirm_payment("D2", &nonce, "0xother", 43, 7, Utc::now()).await.unwrap(),
            Settled::Unapplied,
            "a second payment is not a second sale"
        );
        assert_eq!(s.payment("D2", &nonce).await.unwrap().unwrap().status, "unapplied");
        assert_eq!(s.session(&session).await.unwrap().unwrap().status, "paid");
        let mut hooks = s.claim_webhooks(Utc::now(), 10, 60).await.unwrap();
        assert_eq!(hooks.len(), 2, "the sale, and the merchant is told about the second payment");
        hooks.sort_by_key(|h| h.event.clone());
        assert_eq!(hooks[0].event, "payment.unapplied");
        assert_eq!(
            (hooks[0].payload["payer"].as_str(), hooks[0].payload["digest"].as_str()),
            (Some("0xother"), Some("D2"))
        );
        assert_eq!(hooks[0].payload["sessionStatus"], "paid");
        s.webhook_delivered(hooks[0].id, Utc::now()).await.unwrap();
        hooks.remove(0);
        assert_eq!(hooks[0].payload["paidUntilMs"], 42);
        assert_eq!(hooks[0].payload["platformFee"], "7");
        assert_eq!(hooks[0].payload["metadata"]["a"], 1);
        assert!(s.claim_webhooks(Utc::now(), 10, 60).await.unwrap().is_empty(), "leased");
        s.webhook_delivered(hooks[0].id, Utc::now()).await.unwrap();
        assert!(s.claim_webhooks(Utc::now() + chrono::Duration::minutes(5), 10, 60).await.unwrap().is_empty());
    }

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
        assert_eq!(s.confirm_payment("D1", &nonce, "0xpayer", 42, 7, Utc::now()).await.unwrap(), Settled::Confirmed);
        assert_eq!(s.session_payment_status(&session, "D1").await.unwrap().as_deref(), Some("confirmed"));
        assert_eq!(s.session(&session).await.unwrap().unwrap().status, "paid");
        assert!(s.session_payment_status(&session, "D9").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_payment_for_a_cancelled_session_is_unapplied_and_the_merchant_is_told() {
        let Some(s) = store().await else { return };
        let (m, session, nonce) = fixture(&s).await;
        assert!(s.cancel_session(m, &session).await.unwrap());
        s.submit_payment("D1", &session, &nonce).await.unwrap();
        assert_eq!(s.confirm_payment("D1", &nonce, "0xpayer", 42, 7, Utc::now()).await.unwrap(), Settled::Unapplied);
        let p = s.payment("D1", &nonce).await.unwrap().unwrap();
        assert_eq!((p.status.as_str(), p.payer.as_deref()), ("unapplied", Some("0xpayer")));
        assert_eq!(s.session(&session).await.unwrap().unwrap().status, "cancelled", "the session is not sold");
        let hooks = s.claim_webhooks(Utc::now(), 10, 60).await.unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(
            (hooks[0].event.as_str(), hooks[0].payload["sessionStatus"].as_str()),
            ("payment.unapplied", Some("cancelled"))
        );
        assert_eq!(s.session_payment_status(&session, "D1").await.unwrap().as_deref(), Some("unapplied"));
    }

    #[test]
    fn best_status_prefers_confirmed_then_pending() {
        let v = |x: &[&str]| best_status(x.iter().map(|s| s.to_string()));
        assert_eq!(v(&["rejected", "confirmed", "pending"]).as_deref(), Some("confirmed"));
        assert_eq!(v(&["pending", "unapplied", "rejected"]).as_deref(), Some("unapplied"));
        assert_eq!(v(&["rejected", "pending"]).as_deref(), Some("pending"));
        assert_eq!(v(&["rejected"]).as_deref(), Some("rejected"));
        assert_eq!(v(&[]), None);
    }

    #[tokio::test]
    async fn expiry_waits_for_pending_payments_and_queues_a_webhook() {
        let Some(s) = store().await else { return };
        let (_, session, nonce) = fixture(&s).await;
        s.submit_payment("D1", &session, &nonce).await.unwrap();
        let later = Utc::now() + chrono::Duration::hours(1);
        assert_eq!(s.expire_sessions(later).await.unwrap(), 0, "a pending payment holds the session open");
        s.payment_not_confirmed("D1", &nonce, "the transaction failed", None).await.unwrap();
        assert_eq!(s.expire_sessions(later).await.unwrap(), 1);
        assert_eq!(s.session(&session).await.unwrap().unwrap().status, "expired");
        let hooks = s.claim_webhooks(later, 10, 60).await.unwrap();
        assert_eq!(hooks[0].event, "session.expired");
    }

    #[tokio::test]
    async fn due_payments_and_the_watcher_lock() {
        let Some(s) = store().await else { return };
        let (_, session, nonce) = fixture(&s).await;
        s.submit_payment("D1", &session, &nonce).await.unwrap();
        assert_eq!(s.due_payments(Utc::now() + chrono::Duration::seconds(1), 10).await.unwrap().len(), 1);
        s.payment_not_confirmed("D1", &nonce, "not found yet", Some(Utc::now() + chrono::Duration::minutes(1)))
            .await
            .unwrap();
        assert!(s.due_payments(Utc::now(), 10).await.unwrap().is_empty());
        let first = s.try_watcher_lock().await.unwrap();
        assert!(first.is_some());
        assert!(s.try_watcher_lock().await.unwrap().is_none(), "one writer");
        assert_eq!(s.backlog().await.unwrap(), (1, 1, 0));
    }
}
