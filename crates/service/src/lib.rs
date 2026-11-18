//! `chain-payments-service`: the public session API, the merchant API, price sources, the worker and webhooks.

pub mod api;
pub mod app;
pub mod config;
pub mod metrics;
pub mod prices;
pub mod worker;

/// A timestamp as RFC 3339 (UTC, `Z`), as the APIs and webhooks send them.
pub fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}
