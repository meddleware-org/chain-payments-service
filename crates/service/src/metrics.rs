//! Prometheus text exposition of a few counters and gauges (no client library; the internal port serves it).

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    pub quotes: AtomicU64,
    pub quote_failures: AtomicU64,
    pub payments_submitted: AtomicU64,
    pub payments_confirmed: AtomicU64,
    pub payments_rejected: AtomicU64,
    pub payments_unapplied: AtomicU64,
    pub payments_found: AtomicU64,
    pub webhooks_delivered: AtomicU64,
    pub webhook_failures: AtomicU64,
    pub price_failures: AtomicU64,
    pub sessions_created: AtomicU64,
}

impl Metrics {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// The merchant watch as gauges (one series per merchant object).
    pub fn render_watch(rows: &[(String, bool, bool, bool, i64)]) -> String {
        let mut s = String::new();
        for (name, help, pick) in [
            ("chain_payments_merchant_pending_recipient", "1 while a recipient change is pending on-chain", 0usize),
            (
                "chain_payments_merchant_recipient_unexpected",
                "1 when the on-chain recipient is not the expected one",
                1,
            ),
            ("chain_payments_merchant_quote_key_foreign", "1 when the on-chain quote key is not this service's", 2),
            ("chain_payments_merchant_watch_age_seconds", "Seconds since the worker last read the merchant", 3),
        ] {
            let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} gauge");
            for (m, pending, unexpected, foreign, age) in rows {
                let v = match pick {
                    0 => *pending as i64,
                    1 => *unexpected as i64,
                    2 => *foreign as i64,
                    _ => *age,
                };
                let _ = writeln!(s, "{name}{{merchant=\"{m}\"}} {v}");
            }
        }
        s
    }

    pub fn render(&self, backlog: Option<(i64, i64, i64)>) -> String {
        let mut s = String::new();
        let counters = [
            ("chain_payments_quotes_total", "Quotes signed", &self.quotes),
            ("chain_payments_quote_failures_total", "Quote requests that got no quote", &self.quote_failures),
            ("chain_payments_sessions_created_total", "Checkout sessions created", &self.sessions_created),
            ("chain_payments_payments_submitted_total", "Transactions submitted for a quote", &self.payments_submitted),
            ("chain_payments_payments_confirmed_total", "Payments confirmed on-chain", &self.payments_confirmed),
            (
                "chain_payments_payments_rejected_total",
                "Submitted transactions that did not pay",
                &self.payments_rejected,
            ),
            (
                "chain_payments_payments_unapplied_total",
                "Payments for a session no longer open (the merchant credits or refunds them)",
                &self.payments_unapplied,
            ),
            (
                "chain_payments_payments_found_total",
                "On-chain payments found through events that no checkout submitted",
                &self.payments_found,
            ),
            ("chain_payments_webhooks_delivered_total", "Webhooks delivered", &self.webhooks_delivered),
            ("chain_payments_webhook_failures_total", "Webhook delivery attempts that failed", &self.webhook_failures),
            ("chain_payments_price_failures_total", "Price fetches without an agreed price", &self.price_failures),
        ];
        for (name, help, c) in counters {
            let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}", c.load(Ordering::Relaxed));
        }
        if let Some((open, pending, undelivered)) = backlog {
            for (name, help, v) in [
                ("chain_payments_sessions_open", "Open checkout sessions", open),
                ("chain_payments_payments_pending", "Payments waiting for on-chain confirmation", pending),
                ("chain_payments_webhooks_undelivered", "Webhooks not delivered yet", undelivered),
            ] {
                let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
            }
        }
        s
    }
}
