//! `chain-payments-service`: the public session API, the merchant API, price sources, the worker and webhooks.

/// The two routers.
pub mod api;
/// The shared state and the operations (quote, settle).
pub mod app;
/// Configuration from the environment.
pub mod config;
/// The Prometheus text.
pub mod metrics;
/// The price sources.
pub mod prices;
/// The worker duties.
pub mod worker;

/// A timestamp as RFC 3339 (UTC, `Z`), as the APIs and webhooks send them.
pub fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}
