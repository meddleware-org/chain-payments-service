//! The shared application state and the operations both the API and the worker perform (quoting, settling a payment).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chain_payments_chain_sui::{Expected, HttpTransport, Sui, VerifyError};
use chain_payments_core::money::{format_gbp, format_units, pence_to_units};
use chain_payments_core::quote::QuoteFields;
use chain_payments_core::registry::Method;
use chain_payments_core::session::random_id;
use chain_payments_store::{Quote, Store};
use chrono::Utc;
use serde_json::{Value, json};

use crate::config::Config;
use crate::metrics::Metrics;
use crate::prices::Prices;

/// A pending payment that is still unknown after this long is rejected.
pub const GIVE_UP_AFTER_SECS: i64 = 3600;

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
        if s.status != "open" || s.expires_at <= Utc::now() {
            return Err(OpError::Refused("this checkout is no longer open".into()));
        }
        if !s.methods.iter().any(|m| m == method_id) {
            return Err(OpError::Refused("this payment method is not offered for this checkout".into()));
        }
        let m = self.method(method_id).ok_or_else(|| OpError::Refused("unknown payment method".into()))?;
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
                    "at": Utc::now().to_rfc3339(),
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
        let expires_ms =
            (Utc::now().timestamp_millis() as u64).saturating_add(self.config.quote_ttl.as_millis() as u64);
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
        let signature =
            self.config.quote_signer.sign_quote(&fields).map_err(|e| OpError::Refused(format!("cannot sign: {e}")))?;
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

    /// Checks a submitted payment on-chain once and records the outcome. Returns its status afterwards.
    pub async fn settle(&self, digest: &str) -> Result<String, OpError> {
        let p = self.store.payment(digest).await?.ok_or(OpError::NotFound)?;
        if p.status != "pending" {
            return Ok(p.status);
        }
        let q = self.store.quote(&p.nonce).await?.ok_or(OpError::NotFound)?;
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
        };
        let now = Utc::now();
        match chain.verify_payment(digest, &expected).await {
            Ok(c) => {
                if self.store.confirm_payment(digest, &c.payer, c.paid_until_ms as i64, now).await? {
                    Metrics::inc(&self.metrics.payments_confirmed);
                    tracing::info!(session = %q.session_id, %digest, "payment confirmed");
                    Ok("confirmed".into())
                } else {
                    Metrics::inc(&self.metrics.payments_rejected);
                    Ok("rejected".into())
                }
            }
            Err(e) if e.retryable() => {
                let age = self.store.payment_age_secs(digest, now).await?;
                if age > GIVE_UP_AFTER_SECS {
                    self.store.payment_not_confirmed(digest, &e.to_string(), None).await?;
                    Metrics::inc(&self.metrics.payments_rejected);
                    return Ok("rejected".into());
                }
                let backoff = 2i64.saturating_pow((p.attempts.clamp(0, 8)) as u32).min(300);
                self.store
                    .payment_not_confirmed(digest, &e.to_string(), Some(now + chrono::Duration::seconds(backoff)))
                    .await?;
                Ok("pending".into())
            }
            Err(e) => {
                let reason = match e {
                    VerifyError::Failed => "the transaction failed",
                    _ => "the transaction did not pay this quote",
                };
                self.store.payment_not_confirmed(digest, reason, None).await?;
                Metrics::inc(&self.metrics.payments_rejected);
                Ok("rejected".into())
            }
        }
    }
}
