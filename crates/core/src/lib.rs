//! `chain-payments-core`: the pure parts of Chain Payments.
//!
//! - [`money`]: GBP pence ↔ coin units in fixed point, always rounding the coin amount up;
//! - [`price`]: the median of agreeing price sources, or no price;
//! - [`quote`]: the exact message the Move package verifies, and ed25519 signing;
//! - [`webhook`]: asymmetric webhook signatures;
//! - [`session`]: checkout sessions as merchants create them;
//! - [`registry`]: the payment methods an instance offers.

pub mod money;
pub mod price;
pub mod quote;
pub mod registry;
pub mod session;
pub mod webhook;
