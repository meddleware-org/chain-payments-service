//! The shared application state and the operations both the API and the worker perform (quoting, settling a payment).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chain_payments_chain_sui::{Expected, HttpTransport, Sui, VerifyError};
use chain_payments_core::money::{format_gbp, format_units, pence_to_units};
use chain_payments_core::quote::QuoteFields;
use chain_payments_core::registry::Method;
use chain_payments_core::session::random_id;
use chain_payments_store::{Quote, Settled, Store};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::config::Config;
use crate::metrics::Metrics;
use crate::prices::Prices;

/// A claim whose transaction no full node knows after this long is rejected.
pub const GIVE_UP_AFTER_SECS: i64 = 3600;

/// Whether a retryable verification error ends a claim. Only "the node does not know this transaction" does, and only
/// after [`GIVE_UP_AFTER_SECS`]: an outage of our own full node (an RPC error) is never a reason to reject a real
/// payment, so it is retried (with capped backoff) until the node answers.
pub fn gives_up(e: &VerifyError, age_secs: i64) -> bool {
    matches!(e, VerifyError::NotFound) && age_secs > GIVE_UP_AFTER_SECS
}

pub struct App {
    pub store: Store,
    pub config: Config,
    pub prices: Prices,
    pub chains: HashMap<String, Sui<HttpTransport>>,
    pub metrics: Metrics,
}

pub type Shared = Arc<App>;

#[derive(Debug, thiserror::Error)]
pub enum OpError {
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Refused(String),
    #[error("no price is available right now; try again shortly")]
    NoPrice,
    #[error("too many payments are being checked for this checkout; try again shortly")]
    TooManyClaims,
    #[error("storage: {0}")]
    Store(#[from] chain_payments_store::DbError),
}

impl App {
    pub fn new(store: Store, config: Config) -> anyhow::Result<Self> {
        let prices = Prices::new(
            config.sources.clone(),
            config.gecko_ids.clone(),
            config.min_sources,
            config.max_spread_bps,
            config.price_cache,
        )?;
        let mut chains = HashMap::new();
        for (network, url) in &config.grpc {
            chains.insert(network.clone(), Sui::new(url, Duration::from_secs(10))?);
        }
        Ok(Self { store, config, prices, chains, metrics: Metrics::default() })
    }

    pub fn method(&self, id: &str) -> Option<&Method> {
        self.config.registry.get(id)
    }

    /// The public description of a payment method (what the checkout needs to build the transaction).
    pub fn method_json(m: &Method) -> Value {
        json!({
            "id": m.id, "chain": m.chain, "network": m.network, "symbol": m.symbol, "decimals": m.decimals,
            "coinType": format!("0x{}", m.coin_type), "packageId": m.package_id, "merchantObject": m.merchant_object,
        })
    }

    /// Signs a quote for an open session in one of its methods.
    pub async fn quote(&self, session_id: &str, method_id: &str) -> Result<Value, OpError> {
        let s = self.store.session(session_id).await?.ok_or(OpError::NotFound)?;
        if s.status != "open" || s.expires_at <= OffsetDateTime::now_utc() {
            return Err(OpError::Refused("this checkout is no longer open".into()));
        }
        if !s.methods.iter().any(|m| m == method_id) {
            return Err(OpError::Refused("this payment method is not offered for this checkout".into()));
        }
        let m = self.method(method_id).ok_or_else(|| OpError::Refused("unknown payment method".into()))?;
        // A merchant whose recipient or quote key changed on-chain (or is about to) gets no quotes until it is checked.
        if let Some(why) = self.store.merchant_hold(&m.merchant_object).await? {
            tracing::warn!(merchant = %m.merchant_object, why, "quote refused");
            return Err(OpError::Refused(format!("payments to this merchant are paused: {why}")));
        }
        if self.store.count_quotes(session_id).await? >= self.config.max_quotes_per_session {
            return Err(OpError::Refused("too many quotes for this checkout; start a new one".into()));
        }
        let price = if m.gbp_pegged {
            json!({ "pricePico": "1000000000000", "pegged": "GBP" })
        } else {
            match self.prices.price(&m.price_symbol).await {
                Ok(a) => json!({
                    "pricePico": a.price_pico.to_string(),
                    "spreadBps": a.spread_bps.to_string(),
                    "samples": a.samples.iter().map(|x| json!({ "source": x.source, "pricePico": x.price_pico.to_string() })).collect::<Vec<_>>(),
                    "at": crate::rfc3339(OffsetDateTime::now_utc()),
                }),
                Err(e) => {
                    Metrics::inc(&self.metrics.price_failures);
                    Metrics::inc(&self.metrics.quote_failures);
                    tracing::warn!(symbol = %m.price_symbol, error = %e, "no agreed price");
                    return Err(OpError::NoPrice);
                }
            }
        };
        let price_pico: u128 = price["pricePico"].as_str().and_then(|p| p.parse().ok()).ok_or(OpError::NoPrice)?;
        let amount_pence = u64::try_from(s.amount_pence).map_err(|_| OpError::NoPrice)?;
        let amount = pence_to_units(amount_pence, price_pico, m.decimals).map_err(|_| OpError::NoPrice)?;
        if i64::try_from(amount).is_err() {
            return Err(OpError::Refused("the amount is out of range".into()));
        }
        let nonce = random_id(16);
        let expires_ms = (OffsetDateTime::now_utc().unix_timestamp_nanos() as u64 / 1_000_000)
            .saturating_add(self.config.quote_ttl.as_millis() as u64);
        let fields = QuoteFields {
            merchant_id: format!("{:0>64}", m.merchant_object.trim_start_matches("0x")),
            session: s.id.clone(),
            coin_type: m.coin_type.clone(),
            amount,
            units: s.units as u64,
            period_ms: s.period_ms as u64,
            subscription_ref: s.subscription_ref.clone(),
            expires_ms,
            nonce: nonce.clone(),
        };
        let signature = self
            .config
            .quote_signer
            .as_ref()
            .ok_or_else(|| OpError::Refused("this process does not hold the quote key".into()))?
            .sign_quote(&fields)
            .map_err(|e| OpError::Refused(format!("cannot sign: {e}")))?;
        self.store
            .insert_quote(&Quote {
                nonce: nonce.clone(),
                session_id: s.id.clone(),
                method_id: m.id.clone(),
                coin_type: m.coin_type.clone(),
                amount: amount as i64,
                expires_ms: expires_ms as i64,
                signature: signature.clone(),
                price: price.clone(),
            })
            .await?;
        Metrics::inc(&self.metrics.quotes);
        Ok(json!({
            "nonce": nonce,
            "session": s.id,
            "method": App::method_json(m),
            "amount": amount.to_string(),
            "amountText": format!("{} {}", format_units(amount, m.decimals), m.symbol),
            "priceText": format_gbp(amount_pence),
            "units": s.units,
            "periodMs": s.period_ms.to_string(),
            "subscriptionRef": s.subscription_ref,
            "expiresMs": expires_ms.to_string(),
            "signature": signature,
        }))
    }

    /// Checks a submitted claim (a transaction digest paying one quote) on-chain once and records the outcome. Returns
    /// the claim's status afterwards.
    pub async fn settle(&self, digest: &str, nonce: &str) -> Result<String, OpError> {
        let p = self.store.payment(digest, nonce).await?.ok_or(OpError::NotFound)?;
        if p.status != "pending" {
            return Ok(p.status);
        }
        let q = self.store.quote(&p.nonce).await?.ok_or(OpError::NotFound)?;
        let s = self.store.session(&q.session_id).await?.ok_or(OpError::NotFound)?;
        let m = self.method(&q.method_id).ok_or_else(|| OpError::Refused("unknown payment method".into()))?;
        let Some(chain) = self.chains.get(&m.network) else {
            return Err(OpError::Refused("no full node for this network".into()));
        };
        let expected = Expected {
            package_id: &m.package_id,
            merchant_object: &m.merchant_object,
            session: &q.session_id,
            nonce: &q.nonce,
            coin_type: &q.coin_type,
            amount: q.amount as u64,
            units: s.units as u64,
            subscription_ref: &s.subscription_ref,
        };
        let now = OffsetDateTime::now_utc();
        match chain.verify_payment(digest, &expected).await {
            Ok(c) => match self
                .store
                .confirm_payment(digest, nonce, &c.payer, c.paid_until_ms as i64, c.platform_fee, now)
                .await?
            {
                Settled::Confirmed => {
                    Metrics::inc(&self.metrics.payments_confirmed);
                    tracing::info!(session = %q.session_id, %digest, "payment confirmed");
                    Ok("confirmed".into())
                }
                Settled::Unapplied => {
                    Metrics::inc(&self.metrics.payments_unapplied);
                    tracing::warn!(session = %q.session_id, %digest, "paid on-chain for a session that was no longer open; the merchant is told");
                    Ok("unapplied".into())
                }
                // The other process's outcome stands (and was counted there).
                Settled::Already(status) => Ok(status),
            },
            Err(e) if e.retryable() => {
                let age = self.store.payment_age_secs(digest, nonce, now).await?;
                if gives_up(&e, age) {
                    self.store.payment_not_confirmed(digest, nonce, &e.to_string(), None).await?;
                    Metrics::inc(&self.metrics.payments_rejected);
                    return Ok("rejected".into());
                }
                let backoff = 2i64.saturating_pow((p.attempts.clamp(0, 8)) as u32).min(300);
                self.store
                    .payment_not_confirmed(digest, nonce, &e.to_string(), Some(now + time::Duration::seconds(backoff)))
                    .await?;
                Ok("pending".into())
            }
            Err(e) => {
                let reason = match e {
                    VerifyError::Failed => "the transaction failed",
                    _ => "the transaction did not pay this quote",
                };
                self.store.payment_not_confirmed(digest, nonce, reason, None).await?;
                Metrics::inc(&self.metrics.payments_rejected);
                Ok("rejected".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_unknown_transaction_is_given_up_on() {
        assert!(!gives_up(&VerifyError::NotFound, GIVE_UP_AFTER_SECS));
        assert!(gives_up(&VerifyError::NotFound, GIVE_UP_AFTER_SECS + 1));
        assert!(!gives_up(&VerifyError::Rpc(anyhow::anyhow!("node down")), 10 * GIVE_UP_AFTER_SECS));
    }
}
