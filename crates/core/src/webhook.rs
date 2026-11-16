//! Webhook signatures. Asymmetric, so a merchant verifies with the service's public key and no shared secret exists:
//! `Chain-Payments-Signature: t=<unix seconds>,ed25519=<base64 signature of "<t>.<body>">`. Merchants should refuse a
//! timestamp older than [`MAX_AGE_SECS`] and remember the event id (each event is delivered at least once).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::quote::{Signer, verify};

pub const HEADER: &str = "chain-payments-signature";
pub const MAX_AGE_SECS: u64 = 300;

pub fn sign(signer: &Signer, unix: u64, body: &[u8]) -> String {
    let mut msg = format!("{unix}.").into_bytes();
    msg.extend_from_slice(body);
    format!("t={unix},ed25519={}", STANDARD.encode(signer.sign(&msg)))
}

/// Verifies a header against a body (what a merchant does; also used by tests).
pub fn check(public: &[u8], header: &str, body: &[u8], now_unix: u64) -> bool {
    let mut t = None;
    let mut sig = None;
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", v)) => t = v.parse::<u64>().ok(),
            Some(("ed25519", v)) => sig = STANDARD.decode(v).ok(),
            _ => {}
        }
    }
    let (Some(t), Some(sig)) = (t, sig) else { return false };
    if now_unix.abs_diff(t) > MAX_AGE_SECS {
        return false;
    }
    let mut msg = format!("{t}.").into_bytes();
    msg.extend_from_slice(body);
    verify(public, &msg, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tampering() {
        let s = Signer::from_seed(&[7u8; 32]).unwrap();
        let public = hex::decode(s.public_hex()).unwrap();
        let h = sign(&s, 1000, b"{\"a\":1}");
        assert!(check(&public, &h, b"{\"a\":1}", 1100));
        assert!(!check(&public, &h, b"{\"a\":2}", 1100));
        assert!(!check(&public, &h, b"{\"a\":1}", 2000), "too old");
        assert!(!check(&public, "t=1000", b"{}", 1000));
    }
}
