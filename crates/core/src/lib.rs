//! `chain-payments-core`: the pure parts of Chain Payments.
//!
//! - [`money`]: GBP pence ↔ coin units in fixed point, always rounding the coin amount up;
//! - [`price`]: the median of agreeing price sources, or no price;
//! - [`quote`]: the exact message the Move package verifies, and ed25519 signing;
//! - [`webhook`]: asymmetric webhook signatures;
//! - [`session`]: checkout sessions as merchants create them;
//! - [`registry`]: the payment methods an instance offers.

/// Money and prices in fixed point.
pub mod money;
/// Combining price sources into one agreed price.
pub mod price;
/// The quote message and ed25519 signing.
pub mod quote;
/// The payment methods an instance offers.
pub mod registry;
/// Checkout sessions as merchants create them.
pub mod session;
/// Webhook signatures.
pub mod webhook;
