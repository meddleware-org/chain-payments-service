//! Webhook signatures. Asymmetric, so a merchant verifies with the service's public key and no shared secret exists:
//! `Chain-Payments-Signature: t=<unix seconds>,ed25519=<base64 signature of "<t>.<body>">`. Merchants should refuse a
//! timestamp older than [`MAX_AGE_SECS`] and remember the event id (each event is delivered at least once).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::quote::{Signer, verify};

/// The header that carries the signature (lower case, as HTTP/2 sends it).
pub const HEADER: &str = "chain-payments-signature";
/// How old a signature may be before a merchant should refuse it, in seconds.
pub const MAX_AGE_SECS: u64 = 300;

/// Sign `<unix>.<body>` and return the header value `t=<unix>,ed25519=<base64>`.
pub fn sign(signer: &Signer, unix: u64, body: &[u8]) -> String {
    // The signed message is the timestamp, a dot and the exact body bytes, so neither can be swapped.
    let mut msg = format!("{unix}.").into_bytes();
    msg.extend_from_slice(body);
    format!("t={unix},ed25519={}", STANDARD.encode(signer.sign(&msg)))
}

/// Verifies a header against a body (what a merchant does; also used by tests).
pub fn check(public: &[u8], header: &str, body: &[u8], now_unix: u64) -> bool {
    let mut t = None;
    let mut sig = None;
    // Read `t` and `ed25519` from the header; unknown parts are ignored.
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", v)) => t = v.parse::<u64>().ok(),
            Some(("ed25519", v)) => sig = STANDARD.decode(v).ok(),
            _ => {}
        }
    }
    let (Some(t), Some(sig)) = (t, sig) else { return false };
    // A stale (or far-future) timestamp is refused, which limits replay.
    if now_unix.abs_diff(t) > MAX_AGE_SECS {
        return false;
    }
    let mut msg = format!("{t}.").into_bytes();
    msg.extend_from_slice(body);
    verify(public, &msg, &sig)
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// Round trip and tampering.
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
