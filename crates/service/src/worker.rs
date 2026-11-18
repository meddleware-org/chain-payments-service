//! The worker: one process (a PostgreSQL advisory lock makes it the single writer) that settles pending payments,
//! expires sessions and delivers webhooks at least once with backoff.

use std::time::Duration;

use chain_payments_core::webhook;
use chain_payments_store::Webhook;
use time::OffsetDateTime;

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
    let now = OffsetDateTime::now_utc();
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
    let Some(signer) = app.config.webhook_signer.as_ref() else {
        tracing::error!("this process does not hold the webhook key; webhooks are left for the worker");
        return;
    };
    let sig = webhook::sign(signer, now.unix_timestamp() as u64, &body);
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
                let _ = app.store.webhook_failed(w.id, &reason, now + time::Duration::days(3650)).await;
            } else {
                let backoff = (10i64 * 2i64.saturating_pow(w.attempts.clamp(0, 12) as u32)).min(6 * 3600);
                let _ = app.store.webhook_failed(w.id, &reason, now + time::Duration::seconds(backoff)).await;
            }
        }
    }
}

/// The client for GraphQL reads: no redirects, short timeouts.
fn graphql_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("chain-payments/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()?)
}

/// One pass of every duty (also what the tests call).
pub async fn tick(app: &Shared, client: &reqwest::Client) {
    let now = OffsetDateTime::now_utc();
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

/// How often the slower duties (watching merchants, finding unsubmitted payments) run.
pub const SLOW_DUTY_EVERY: Duration = Duration::from_secs(60);
/// GraphQL pages read per package per pass (50 events each).
const EVENT_PAGES_PER_PASS: usize = 5;

/// Reads every registry merchant object and records its state; a pending recipient, an unexpected recipient or a
/// foreign quote key holds quoting for that merchant (`Store::merchant_hold`). A merchant the nodes cannot read (or
/// disagree about) is marked unexpected too: an unknown state is not a known-good one.
pub async fn watch_merchants(app: &Shared) {
    let mut seen = std::collections::BTreeSet::new();
    for m in &app.config.registry.methods {
        if !seen.insert(m.merchant_object.clone()) {
            continue;
        }
        let Some(chain) = app.chains.get(&m.network) else { continue };
        let now = OffsetDateTime::now_utc();
        let r = match chain.merchant_state(&m.merchant_object).await {
            Ok(st) => {
                let unexpected = m
                    .recipient
                    .as_deref()
                    .is_some_and(|want| chain_payments_chain_sui::normalize(want) != st.recipient);
                let foreign = st.quote_key != app.config.quote_public;
                if unexpected || foreign || st.pending_recipient.is_some() {
                    tracing::error!(merchant = %m.merchant_object, ?st, unexpected, foreign, "merchant changed on-chain");
                }
                app.store
                    .record_merchant_watch(
                        &m.merchant_object,
                        &st.recipient,
                        st.pending_recipient.as_deref(),
                        &st.quote_key,
                        st.paused,
                        unexpected,
                        foreign,
                        now,
                    )
                    .await
            }
            Err(e) => {
                tracing::error!(merchant = %m.merchant_object, error = %e, "merchant unreadable");
                app.store.record_merchant_watch(&m.merchant_object, "?", None, "?", false, true, false, now).await
            }
        };
        if let Err(e) = r {
            tracing::error!(error = %e, "record merchant watch");
        }
    }
}

/// Finds `Paid` events of each registry package that no checkout submitted (a closed tab, a failed submission) and
/// claims them; the next tick verifies each through the full nodes like any other claim.
pub async fn reconcile(app: &Shared, client: &reqwest::Client) {
    let mut seen = std::collections::BTreeSet::new();
    for m in &app.config.registry.methods {
        if !seen.insert(m.package_id.clone()) {
            continue;
        }
        let Some(url) = app.config.graphql.get(&m.network) else { continue };
        if let Err(e) = reconcile_package(app, client, url, &m.package_id).await {
            tracing::warn!(package = %m.package_id, error = %e, "reconcile");
        }
    }
}

/// [`reconcile`] for one package and endpoint (also what the tests call).
pub async fn reconcile_package(
    app: &Shared,
    client: &reqwest::Client,
    url: &str,
    package_id: &str,
) -> anyhow::Result<()> {
    let mut cursor = app.store.event_cursor(package_id).await?;
    for _ in 0..EVENT_PAGES_PER_PASS {
        let page = chain_payments_chain_sui::paid_events(client, url, package_id, cursor.as_deref()).await?;
        for e in &page.events {
            if app.store.claim_found_payment(&e.digest, &e.nonce).await? {
                Metrics::inc(&app.metrics.payments_found);
                tracing::info!(digest = %e.digest, "found a payment no checkout submitted");
            }
        }
        if let Some(c) = &page.end_cursor {
            app.store.set_event_cursor(package_id, c).await?;
            cursor = Some(c.clone());
        }
        if !page.has_next {
            break;
        }
    }
    Ok(())
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
    let chain_client = graphql_client()?;
    let mut last_slow: Option<std::time::Instant> = None;
    loop {
        tick(&app, &client).await;
        if last_slow.is_none_or(|t| t.elapsed() >= SLOW_DUTY_EVERY) {
            watch_merchants(&app).await;
            reconcile(&app, &chain_client).await;
            last_slow = Some(std::time::Instant::now());
        }
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
