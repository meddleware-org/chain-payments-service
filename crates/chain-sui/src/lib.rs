//! The Sui module of Chain Payments: verifies that a transaction paid a quote, by its digest, over the full node's
//! gRPC-web API. The protobuf reading and the gRPC-web client are `access-gate-gateway-core`'s (one implementation for
//! the platform); this crate adds an HTTP transport and the `Paid` event check.
//!
//! A payment is confirmed only when the transaction's effects report success AND it emitted exactly the package's
//! `chain_payments::Paid` event for the expected merchant object, session, nonce, coin type, amount, units and
//! subscription reference (every quote field the event carries). Everything is compared after normalisation; anything
//! missing fails closed.

use std::time::Duration;

use access_gate_gateway_core::chain::{
    EVENT_JSON, EVENT_SENDER, EVENT_TYPE, EVENTS_EVENTS, EXECUTED_EVENTS, LEDGER_GET_TRANSACTION, RESP_TRANSACTION,
    build_get_transaction, effects_succeeded,
};
use access_gate_gateway_core::grpc::{
    Field, GRPC_NOT_FOUND, GrpcStatus, GrpcWeb, MAX_GRPC_MESSAGE_BYTES, ProtoReader, Transport, field_bytes, field_str,
    value_find_string,
};
use access_gate_gateway_core::sig::{normalize_address, normalize_move_type};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// gRPC-web over reqwest (rustls with the ring provider).
pub struct HttpTransport {
    client: reqwest::Client,
}

impl HttpTransport {
    pub fn new(timeout: Duration) -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .user_agent(concat!("chain-payments/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .no_proxy()
            .connect_timeout(Duration::from_secs(5).min(timeout))
            .timeout(timeout)
            .build()?;
        Ok(Self { client })
    }
}

impl Transport for HttpTransport {
    async fn post_grpc_web(&self, url: &str, body: Vec<u8>) -> anyhow::Result<(Option<String>, Vec<u8>)> {
        let r = self
            .client
            .post(url)
            .header("content-type", "application/grpc-web+proto")
            .header("accept", "application/grpc-web+proto")
            .body(body)
            .send()
            .await?;
        if !r.status().is_success() {
            anyhow::bail!("gRPC-web HTTP {}", r.status());
        }
        let status = r.headers().get("grpc-status").and_then(|v| v.to_str().ok()).map(str::to_string);
        if r.content_length().is_some_and(|n| n > MAX_GRPC_MESSAGE_BYTES as u64) {
            anyhow::bail!("gRPC-web response too large");
        }
        let bytes = r.bytes().await?;
        if bytes.len() > MAX_GRPC_MESSAGE_BYTES {
            anyhow::bail!("gRPC-web response too large");
        }
        Ok((status, bytes.to_vec()))
    }

    async fn sleep_ms(&self, ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
}

/// What the payment must match.
#[derive(Debug, Clone)]
pub struct Expected<'a> {
    pub package_id: &'a str,
    pub merchant_object: &'a str,
    pub session: &'a str,
    pub nonce: &'a str,
    /// Canonical coin type (`000…002::sui::SUI`).
    pub coin_type: &'a str,
    pub amount: u64,
    /// The session's units and subscription reference. The nonce already names one signed quote; checking these too means
    /// a quote signed by any other key the merchant's cap may have set cannot buy more than this session sold.
    pub units: u64,
    pub subscription_ref: &'a str,
}

/// A confirmed payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmed {
    pub payer: String,
    pub amount: u64,
    pub units: u64,
    /// 0 when the payment extended no ledger.
    pub paid_until_ms: u64,
    /// Of `amount`, what the package sent to the platform treasury (the merchant received the rest). 0 when the fee
    /// rounded to zero, which the event's JSON may render as an absent value.
    pub platform_fee: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The node does not know the transaction (yet): retry.
    #[error("the transaction is not known yet")]
    NotFound,
    #[error("the transaction failed")]
    Failed,
    #[error("the transaction did not pay this quote")]
    NoMatchingPayment,
    #[error("the full node could not be asked: {0}")]
    Rpc(anyhow::Error),
}

impl VerifyError {
    pub fn retryable(&self) -> bool {
        matches!(self, VerifyError::NotFound | VerifyError::Rpc(_))
    }
}

/// A transaction digest: base58, 32 bytes (43 or 44 characters).
pub fn is_digest(s: &str) -> bool {
    (32..=44).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
}

/// One or more full nodes of one network. With more than one, a payment counts only when every node reports it the same
/// way: a node that is wrong (or lying) can then neither credit a payment that did not happen nor make a real one look
/// rejected; a disagreement is reported as an RPC problem, so the payment is retried and the disagreement is logged.
pub struct Sui<T: Transport> {
    nodes: Vec<GrpcWeb<T>>,
}

impl Sui<HttpTransport> {
    pub fn new(fullnode_urls: &[String], timeout: Duration) -> anyhow::Result<Self> {
        anyhow::ensure!(!fullnode_urls.is_empty(), "at least one full node");
        let nodes = fullnode_urls
            .iter()
            .map(|u| Ok(GrpcWeb::new(HttpTransport::new(timeout)?, u.clone())))
            .collect::<anyhow::Result<_>>()?;
        Ok(Self { nodes })
    }
}

impl<T: Transport> Sui<T> {
    pub fn with_transport(transport: T, fullnode_url: &str) -> Self {
        Self { nodes: vec![GrpcWeb::new(transport, fullnode_url.to_string())] }
    }

    pub fn with_transports(nodes: Vec<(T, String)>) -> Self {
        Self { nodes: nodes.into_iter().map(|(t, u)| GrpcWeb::new(t, u)).collect() }
    }

    pub async fn verify_payment(&self, digest: &str, expected: &Expected<'_>) -> Result<Confirmed, VerifyError> {
        if !is_digest(digest) {
            return Err(VerifyError::NoMatchingPayment);
        }
        let mut answers = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            answers.push(Self::ask(node, digest, expected).await);
        }
        agree(answers)
    }

    async fn ask(node: &GrpcWeb<T>, digest: &str, expected: &Expected<'_>) -> Result<Confirmed, VerifyError> {
        let resp = match node.call(LEDGER_GET_TRANSACTION, build_get_transaction(digest)).await {
            Ok(r) => r,
            Err(e) => {
                return Err(match e.downcast_ref::<GrpcStatus>() {
                    Some(GrpcStatus(code)) if *code == GRPC_NOT_FOUND => VerifyError::NotFound,
                    _ => VerifyError::Rpc(e),
                });
            }
        };
        check_response(&resp, expected)
    }
}

/// Combines the nodes' answers: the same confirmation from all, or else the most cautious answer. An RPC failure, or a
/// confirmation next to anything else, is `Rpc` (retry later); "not known yet" anywhere is `NotFound`; a rejection needs
/// every node to give the same one.
pub fn agree(answers: Vec<Result<Confirmed, VerifyError>>) -> Result<Confirmed, VerifyError> {
    let mut answers = answers.into_iter();
    let Some(first) = answers.next() else { return Err(VerifyError::Rpc(anyhow::anyhow!("no full node configured"))) };
    let rest: Vec<_> = answers.collect();
    if rest.is_empty() {
        return first;
    }
    let all = std::iter::once(&first).chain(rest.iter());
    if let Some(Err(VerifyError::Rpc(e))) = all.clone().find(|a| matches!(a, Err(VerifyError::Rpc(_)))) {
        return Err(VerifyError::Rpc(anyhow::anyhow!("a full node could not be asked: {e}")));
    }
    let confirmed: Vec<&Confirmed> = all.clone().filter_map(|a| a.as_ref().ok()).collect();
    if !confirmed.is_empty() {
        if confirmed.len() == rest.len() + 1 && confirmed.iter().all(|c| *c == confirmed[0]) {
            return first;
        }
        if all.clone().any(|a| matches!(a, Err(VerifyError::NotFound))) && confirmed.iter().all(|c| *c == confirmed[0])
        {
            return Err(VerifyError::NotFound);
        }
        return Err(VerifyError::Rpc(anyhow::anyhow!("the full nodes disagree about this transaction")));
    }
    if all.clone().any(|a| matches!(a, Err(VerifyError::NotFound))) {
        return Err(VerifyError::NotFound);
    }
    let same = |a: &Result<Confirmed, VerifyError>, b: &Result<Confirmed, VerifyError>| {
        matches!(
            (a, b),
            (Err(VerifyError::Failed), Err(VerifyError::Failed))
                | (Err(VerifyError::NoMatchingPayment), Err(VerifyError::NoMatchingPayment))
        )
    };
    if rest.iter().all(|r| same(&first, r)) {
        first
    } else {
        Err(VerifyError::Rpc(anyhow::anyhow!("the full nodes disagree about this transaction")))
    }
}

fn b64(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}

fn u64_field(json: &[u8], key: &str) -> Option<u64> {
    value_find_string(json, key)
        .filter(|s| s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
}

/// Checks a `GetTransactionResponse` (status and events) against what the quote expects.
pub fn check_response(resp: &[u8], expected: &Expected<'_>) -> Result<Confirmed, VerifyError> {
    let tx = field_bytes(resp, RESP_TRANSACTION).ok_or(VerifyError::NotFound)?;
    if !effects_succeeded(tx) {
        return Err(VerifyError::Failed);
    }
    let want_type = normalize_move_type(&format!("{}::chain_payments::Paid", expected.package_id));
    let merchant = normalize_address(expected.merchant_object);
    let events = field_bytes(tx, EXECUTED_EVENTS).ok_or(VerifyError::NoMatchingPayment)?;
    for f in ProtoReader::new(events) {
        let Field::Len(EVENTS_EVENTS, ev) = f else { continue };
        if !field_str(ev, EVENT_TYPE).is_some_and(|t| normalize_move_type(t) == want_type) {
            continue;
        }
        let Some(json) = field_bytes(ev, EVENT_JSON) else { continue };
        let matches = value_find_string(json, "merchant_id").is_some_and(|m| normalize_address(&m) == merchant)
            && value_find_string(json, "session").and_then(|s| b64(&s)).as_deref() == Some(expected.session.as_bytes())
            && value_find_string(json, "nonce").and_then(|s| b64(&s)).as_deref() == Some(expected.nonce.as_bytes())
            && value_find_string(json, "coin_type").as_deref() == Some(expected.coin_type)
            && u64_field(json, "amount") == Some(expected.amount)
            && u64_field(json, "units") == Some(expected.units)
            && match value_find_string(json, "subscription_ref") {
                Some(r) => b64(&r).as_deref() == Some(expected.subscription_ref.as_bytes()),
                // The package's event always has the field; an empty vector may be rendered as an absent value.
                None => expected.subscription_ref.is_empty(),
            };
        if !matches {
            continue;
        }
        let payer = value_find_string(json, "payer")
            .or_else(|| field_str(ev, EVENT_SENDER).map(str::to_string))
            .map(|p| normalize_address(&p))
            .ok_or(VerifyError::NoMatchingPayment)?;
        return Ok(Confirmed {
            payer,
            amount: expected.amount,
            units: expected.units,
            paid_until_ms: u64_field(json, "paid_until_ms").unwrap_or(0),
            platform_fee: u64_field(json, "platform_fee").unwrap_or(0),
        });
    }
    Err(VerifyError::NoMatchingPayment)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(payer: &str) -> Result<Confirmed, VerifyError> {
        Ok(Confirmed { payer: payer.into(), amount: 5, units: 1, paid_until_ms: 9, platform_fee: 0 })
    }

    #[test]
    fn nodes_must_agree() {
        use VerifyError::*;
        let rpc = || Err(Rpc(anyhow::anyhow!("down")));
        assert!(agree(vec![ok("a")]).is_ok(), "one node is trusted as configured");
        assert!(agree(vec![ok("a"), ok("a")]).is_ok());
        assert!(matches!(agree(vec![ok("a"), ok("b")]), Err(Rpc(_))), "different confirmations");
        assert!(
            matches!(agree(vec![ok("a"), Err(NoMatchingPayment)]), Err(Rpc(_))),
            "a lie either way is a disagreement"
        );
        assert!(matches!(agree(vec![Err(Failed), ok("a")]), Err(Rpc(_))));
        assert!(matches!(agree(vec![ok("a"), Err(NotFound)]), Err(NotFound)), "not on every node yet");
        assert!(matches!(agree(vec![ok("a"), rpc()]), Err(Rpc(_))));
        assert!(matches!(agree(vec![Err(NoMatchingPayment), Err(NoMatchingPayment)]), Err(NoMatchingPayment)));
        assert!(matches!(agree(vec![Err(NoMatchingPayment), Err(Failed)]), Err(Rpc(_))));
        assert!(matches!(agree(vec![Err(NoMatchingPayment), Err(NotFound)]), Err(NotFound)));
        assert!(matches!(agree(vec![]), Err(Rpc(_))));
    }

    // A real testnet payment (chain-payments-sui's throwaway TEST merchant), its GetTransaction response recorded raw.
    const PKG: &str = "0x5f67109c6b436fc0c0415d7f3e63ca10d374d8c4bb5e3b1f087cabb1c785bc14";
    const MERCHANT: &str = "0x30b6d544652d35d4a481fa7e45adf8e514b9ae1596377e837b6fdf36d967dae8";
    const SUI: &str = "0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
    const DIGEST: &str = "7AkSLeZfxX2qURL2oHYmKkf3AKNaunJBJLski7TzGUYR";

    fn expected() -> Expected<'static> {
        Expected {
            package_id: PKG,
            merchant_object: MERCHANT,
            session: "live-test-1",
            nonce: "nonce-live-1",
            coin_type: SUI,
            amount: 1000,
            units: 1,
            subscription_ref: "acct-live",
        }
    }

    #[test]
    fn recorded_payment_is_confirmed_and_any_difference_is_not() {
        let resp = include_bytes!("../../../fixtures/sui-paid-transaction.bin");
        let c = check_response(resp, &expected()).unwrap();
        assert_eq!(c.payer, "0xa991ae11b0785718cd3ad1c616e804a4c083f431b3144bb845bdec651164864a");
        assert_eq!((c.amount, c.units), (1000, 1));
        assert!(c.paid_until_ms > 0);
        assert_eq!(c.platform_fee, 0, "recorded from the first package, before the platform fee");
        for wrong in [
            Expected { amount: 999, ..expected() },
            Expected { session: "other", ..expected() },
            Expected { nonce: "other", ..expected() },
            Expected { merchant_object: "0x1", ..expected() },
            Expected { package_id: "0x2", ..expected() },
            Expected { units: 2, ..expected() },
            Expected { subscription_ref: "acct-other", ..expected() },
            Expected { subscription_ref: "", ..expected() },
            Expected {
                coin_type: "0000000000000000000000000000000000000000000000000000000000000002::usdc::USDC",
                ..expected()
            },
        ] {
            assert!(matches!(check_response(resp, &wrong), Err(VerifyError::NoMatchingPayment)));
        }
        assert!(matches!(check_response(&[], &expected()), Err(VerifyError::NotFound)));
    }

    #[test]
    fn digests() {
        assert!(is_digest(DIGEST));
        assert!(!is_digest("0x1234"));
        assert!(!is_digest(&"A".repeat(60)));
    }

    /// Against the live testnet full node when `LIVE_SUI=1` (the release check runs it); otherwise it returns at once.
    #[tokio::test]
    async fn live_testnet() {
        if std::env::var("LIVE_SUI").as_deref() != Ok("1") {
            return;
        }
        let sui = Sui::new(&["https://fullnode.testnet.sui.io:443".to_string()], Duration::from_secs(15)).unwrap();
        let c = sui.verify_payment(DIGEST, &expected()).await.unwrap();
        assert_eq!(c.amount, 1000);
    }
}
