//! The worker: one process (a PostgreSQL advisory lock makes it the single writer) that settles pending payments,
//! expires sessions and delivers webhooks at least once with backoff.

use std::time::Duration;

use chain_payments_core::webhook;
use chain_payments_store::Webhook;
use chrono::Utc;

use crate::app::Shared;
use crate::metrics::Metrics;

/// Webhook attempts before a delivery is left for a person (it stays in the outbox, visible in metrics).
pub const MAX_WEBHOOK_ATTEMPTS: i32 = 20;

pub fn webhook_client() -> anyhow::Result<reqwest::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Ok(reqwest::Client::builder()
        .user_agent(concat!("chain-payments/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()?)
}

/// Webhook targets: `https://` anywhere, or plain `http://` only to an in-cluster Service (`*.svc` / `*.svc.cluster.local`).
pub fn webhook_url_allowed(url: &str) -> bool {
    let Ok(u) = url::Url::parse(url) else { return false };
    if !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    match (u.scheme(), u.host_str()) {
        ("https", Some(_)) => true,
        ("http", Some(h)) => h.ends_with(".svc") || h.ends_with(".svc.cluster.local"),
        _ => false,
    }
}

async fn deliver(app: &Shared, client: &reqwest::Client, w: &Webhook) {
    let now = Utc::now();
    let url = match app.store.merchant(w.merchant_id).await {
        Ok(Some(m)) => m.webhook_url,
        _ => None,
    };
    let Some(url) = url.filter(|u| webhook_url_allowed(u)) else {
        // No endpoint: the merchant polls instead; nothing to retry.
        let _ = app.store.webhook_delivered(w.id, now).await;
        return;
    };
    let body =
        serde_json::to_vec(&serde_json::json!({ "id": w.id, "event": w.event, "data": w.payload })).unwrap_or_default();
    let sig = webhook::sign(&app.config.webhook_signer, now.timestamp() as u64, &body);
    let r = client
        .post(&url)
        .header("content-type", "application/json")
        .header(webhook::HEADER, sig)
        .header("chain-payments-event-id", w.id.to_string())
        .body(body)
        .send()
        .await;
    match r {
        Ok(resp) if resp.status().is_success() => {
            let _ = app.store.webhook_delivered(w.id, now).await;
            Metrics::inc(&app.metrics.webhooks_delivered);
        }
        other => {
            Metrics::inc(&app.metrics.webhook_failures);
            let reason = match other {
                Ok(resp) => format!("HTTP {}", resp.status()),
                Err(e) => format!("not delivered: {}", if e.is_timeout() { "timeout" } else { "connection failed" }),
            };
            if w.attempts >= MAX_WEBHOOK_ATTEMPTS {
                tracing::error!(id = %w.id, %reason, "webhook gave up; left in the outbox");
                let _ = app.store.webhook_failed(w.id, &reason, now + chrono::Duration::days(3650)).await;
            } else {
                let backoff = (10i64 * 2i64.saturating_pow(w.attempts.clamp(0, 12) as u32)).min(6 * 3600);
                let _ = app.store.webhook_failed(w.id, &reason, now + chrono::Duration::seconds(backoff)).await;
            }
        }
    }
}

/// One pass of every duty (also what the tests call).
pub async fn tick(app: &Shared, client: &reqwest::Client) {
    let now = Utc::now();
    match app.store.due_payments(now, 50).await {
        Ok(due) => {
            for p in due {
                if let Err(e) = app.settle(&p.digest, &p.nonce).await {
                    tracing::warn!(digest = %p.digest, error = %e, "settle");
                }
            }
        }
        Err(e) => tracing::error!(error = %e, "due payments"),
    }
    if let Err(e) = app.store.expire_sessions(now).await {
        tracing::error!(error = %e, "expire sessions");
    }
    match app.store.claim_webhooks(now, 20, 60).await {
        Ok(hooks) => {
            for w in &hooks {
                deliver(app, client, w).await;
            }
        }
        Err(e) => tracing::error!(error = %e, "claim webhooks"),
    }
}

/// Runs until `stop` resolves, holding the single-writer lock.
pub async fn run(app: Shared, stop: impl std::future::Future<Output = ()>) -> anyhow::Result<()> {
    let client = webhook_client()?;
    tokio::pin!(stop);
    let _lock = loop {
        match app.store.try_watcher_lock().await {
            Ok(Some(c)) => break c,
            Ok(None) => tracing::info!("another worker holds the lock; waiting"),
            Err(e) => tracing::warn!(error = %e, "cannot take the lock yet"),
        }
        tokio::select! {
            _ = &mut stop => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
    };
    tracing::info!("worker running");
    loop {
        tick(&app, &client).await;
        tokio::select! {
            _ = &mut stop => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(3)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn webhook_targets() {
        assert!(super::webhook_url_allowed("https://example.org/hook"));
        assert!(super::webhook_url_allowed("http://link-in-bio-api.link-in-bio.svc:8081/internal/v1/payments"));
        assert!(!super::webhook_url_allowed("http://example.org/hook"));
        assert!(!super::webhook_url_allowed("https://user:pw@example.org/"));
        assert!(!super::webhook_url_allowed("ftp://example.org/"));
    }
}
