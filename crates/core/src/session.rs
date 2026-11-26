//! Checkout sessions: what a merchant asks to be paid, validated at the boundary.

use serde::{Deserialize, Serialize};

use crate::quote::MAX_ID_BYTES;

/// The longest description, in characters.
pub const MAX_DESCRIPTION: usize = 120;
/// The largest metadata, in bytes of JSON.
pub const MAX_METADATA_BYTES: usize = 4096;
/// The longest a session stays open.
pub const MAX_SESSION_SECS: u64 = 24 * 3600;
/// How long a session stays open when the merchant does not say.
pub const DEFAULT_SESSION_SECS: u64 = 30 * 60;

/// Where a session is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Waiting for payment.
    Open,
    /// Paid on chain.
    Paid,
    /// Not paid before it expired.
    Expired,
    /// Cancelled by the merchant.
    Cancelled,
}

impl Status {
    /// The status as stored and served.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Paid => "paid",
            Status::Expired => "expired",
            Status::Cancelled => "cancelled",
        }
    }
    /// Read a stored status; unknown text is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Status::Open),
            "paid" => Some(Status::Paid),
            "expired" => Some(Status::Expired),
            "cancelled" => Some(Status::Cancelled),
            _ => None,
        }
    }
}

/// A merchant's request to create a session.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewSession {
    /// Price in pence (GBP).
    pub amount_pence: u64,
    /// What the buyer sees: one line, at most 120 characters.
    pub description: String,
    /// Units bought (months, for a subscription). Default 1.
    #[serde(default = "one")]
    pub units: u64,
    /// The merchant's opaque reference whose prepaid period this extends (empty: a one-off payment).
    #[serde(default)]
    pub subscription_ref: String,
    /// The period each unit buys, in milliseconds; set together with `subscription_ref`.
    #[serde(default)]
    pub period_ms: u64,
    /// Methods the buyer may use (ids from the registry); empty means every method the merchant enables.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Returned unchanged in webhooks.
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// How long the session stays open, in seconds (60 to 86,400); the default applies when absent.
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
}

/// The default number of units.
fn one() -> u64 {
    1
}

/// Why a session request was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The request is invalid, for the reason given (it names the field).
    #[error("{0}")]
    Invalid(&'static str),
}

impl NewSession {
    /// Validate a request at the boundary: amount, description, units, reference and period together, method count, metadata size and lifetime.
    pub fn check(&self) -> Result<(), SessionError> {
        // £100,000 is the ceiling for one session; zero is not a price.
        if self.amount_pence == 0 || self.amount_pence > 10_000_000 {
            return Err(SessionError::Invalid("amountPence must be between 1 and 10,000,000"));
        }
        // The description is one line of plain text: no control characters.
        let d = self.description.trim();
        if d.is_empty() || d.chars().count() > MAX_DESCRIPTION || d.chars().any(char::is_control) {
            return Err(SessionError::Invalid("description must be 1 to 120 characters of one line"));
        }
        // Up to ten years of months.
        if self.units == 0 || self.units > 120 {
            return Err(SessionError::Invalid("units must be between 1 and 120"));
        }
        // The reference goes on chain, so it uses a restricted alphabet and the on-chain bound.
        if self.subscription_ref.len() > MAX_ID_BYTES
            || !self.subscription_ref.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(SessionError::Invalid("subscriptionRef must be at most 64 of [A-Za-z0-9_-]"));
        }
        // A reference without a period (or a period without a reference) is meaningless.
        if self.subscription_ref.is_empty() != (self.period_ms == 0) {
            return Err(SessionError::Invalid("subscriptionRef and periodMs go together"));
        }
        // Bound the list so a request cannot make the server do unbounded work.
        if self.methods.len() > 32 {
            return Err(SessionError::Invalid("too many methods"));
        }
        // Metadata is returned in webhooks; its size is bounded and an unserialisable value counts as too large.
        if serde_json::to_vec(&self.metadata).map(|v| v.len()).unwrap_or(usize::MAX) > MAX_METADATA_BYTES {
            return Err(SessionError::Invalid("metadata is larger than 4 KiB"));
        }
        // A session lasts between one minute and a day.
        if let Some(e) = self.expires_in_secs
            && !(60..=MAX_SESSION_SECS).contains(&e)
        {
            return Err(SessionError::Invalid("expiresInSecs must be between 60 and 86400"));
        }
        Ok(())
    }
}

/// A random identifier (hex) from the operating system's generator.
pub fn random_id(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    // The operating system's generator, never a seeded or predictable one.
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut buf).expect("system random");
    hex::encode(buf)
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// A valid minimal session request.
    fn base() -> NewSession {
        serde_json::from_value(serde_json::json!({ "amountPence": 300, "description": "Link in Bio, 1 month" }))
            .unwrap()
    }

    /// Checks.
    #[test]
    fn checks() {
        assert!(base().check().is_ok());
        let mut s = base();
        s.subscription_ref = "acct".into();
        assert!(s.check().is_err(), "a reference needs a period");
        s.period_ms = 2_629_800_000;
        assert!(s.check().is_ok());
        let mut s = base();
        s.description = "a\nb".into();
        assert!(s.check().is_err());
        assert!(
            serde_json::from_value::<NewSession>(serde_json::json!({ "amountPence": 1, "description": "x", "x": 1 }))
                .is_err()
        );
        assert_eq!(random_id(16).len(), 32);
    }
}
