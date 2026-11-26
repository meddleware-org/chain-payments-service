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
    EVENT_JSON, EVENT_SENDER, EVENT_TYPE, EVENTS_EVENTS, EXECUTED_EVENTS, FIELDMASK_PATHS, GO_OBJECT, GO_OBJECT_ID,
    GO_READ_MASK, LEDGER_GET_OBJECT, LEDGER_GET_TRANSACTION, OBJECT_JSON, RESP_TRANSACTION, build_get_transaction,
    effects_succeeded,
};
use access_gate_gateway_core::grpc::{
    Field, GRPC_NOT_FOUND, GrpcStatus, GrpcWeb, MAX_GRPC_MESSAGE_BYTES, ProtoReader, ProtoWriter, Transport,
    field_bytes, field_str, value_as_bool, value_field, value_find_string,
};
use access_gate_gateway_core::sig::{normalize_address, normalize_move_type};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// gRPC-web over reqwest (rustls with the ring provider).
pub struct HttpTransport {
    /// The HTTP client: HTTPS only, no redirects, no proxy and a timeout.
    client: reqwest::Client,
}

impl HttpTransport {
    /// Build the transport; `timeout` bounds every request.
    pub fn new(timeout: Duration) -> anyhow::Result<Self> {
        // Install the ring provider once; a second install is an error that is deliberately ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .user_agent(concat!("chain-payments/", env!("CARGO_PKG_VERSION")))
            // A full node never redirects; following one could send the request somewhere else.
            .redirect(reqwest::redirect::Policy::none())
            // Plain http is refused: the answer decides whether money was received.
            .https_only(true)
            // No environment proxy: the request goes where the configuration says.
            .no_proxy()
            // Connecting is bounded separately and never longer than the whole request.
            .connect_timeout(Duration::from_secs(5).min(timeout))
            .timeout(timeout)
            .build()?;
        Ok(Self { client })
    }
}

impl Transport for HttpTransport {
    /// POST a gRPC-web request and return the status trailer and the body, refusing a non-2xx answer or one over the size bound.
    async fn post_grpc_web(&self, url: &str, body: Vec<u8>) -> anyhow::Result<(Option<String>, Vec<u8>)> {
        let r = self
            .client
            .post(url)
            // The gRPC-web wire format: protobuf frames over plain HTTP.
            .header("content-type", "application/grpc-web+proto")
            .header("accept", "application/grpc-web+proto")
            .body(body)
            .send()
            .await
            // reqwest's error text names the request URL, which can carry a credential (a full node behind a key): drop it
            // (CONF lens); the failure class and the cause stay.
            .map_err(reqwest::Error::without_url)?;
        // A non-2xx status is a transport failure, reported with the status code only.
        if !r.status().is_success() {
            anyhow::bail!("gRPC-web HTTP {}", r.status());
        }
        // The gRPC status travels in a header for a trailers-only answer.
        let status = r.headers().get("grpc-status").and_then(|v| v.to_str().ok()).map(str::to_string);
        // The declared size is checked before reading, and the real size after: an answer is never buffered without bound.
        if r.content_length().is_some_and(|n| n > MAX_GRPC_MESSAGE_BYTES as u64) {
            anyhow::bail!("gRPC-web response too large");
        }
        let bytes = r.bytes().await.map_err(reqwest::Error::without_url)?;
        if bytes.len() > MAX_GRPC_MESSAGE_BYTES {
            anyhow::bail!("gRPC-web response too large");
        }
        // The body is returned with the status; the shared gRPC-web client decodes the frames.
        Ok((status, bytes.to_vec()))
    }

    /// Sleep (the library retries a call after a pause).
    async fn sleep_ms(&self, ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// The clock in epoch milliseconds.
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
}

/// What the payment must match.
#[derive(Debug, Clone)]
pub struct Expected<'a> {
    /// The Move package the `Paid` event must come from.
    pub package_id: &'a str,
    /// The merchant object the payment must name.
    pub merchant_object: &'a str,
    /// The checkout session the payment must name.
    pub session: &'a str,
    /// The quote nonce the payment must name.
    pub nonce: &'a str,
    /// Canonical coin type (`000…002::sui::SUI`).
    pub coin_type: &'a str,
    /// The amount in the coin's smallest unit.
    pub amount: u64,
    /// The session's units and subscription reference. The nonce already names one signed quote; checking these too means
    /// a quote signed by any other key the merchant's cap may have set cannot buy more than this session sold.
    pub units: u64,
    /// The merchant's subscription reference for the session (empty for a one-off payment).
    pub subscription_ref: &'a str,
}

/// A confirmed payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmed {
    /// The paying address (the event's payer, else the transaction sender).
    pub payer: String,
    /// The amount paid, in the coin's smallest unit.
    pub amount: u64,
    /// The units bought.
    pub units: u64,
    /// 0 when the payment extended no ledger.
    pub paid_until_ms: u64,
    /// Of `amount`, what the package sent to the platform treasury (the merchant received the rest). 0 when the fee
    /// rounded to zero, which the event's JSON may render as an absent value.
    pub platform_fee: u64,
}

/// The `Paid` event exists, in a successful transaction, and matches every quote field.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The node does not know the transaction (yet): retry.
    #[error("the transaction is not known yet")]
    NotFound,
    /// The transaction was found but its effects report a failure.
    #[error("the transaction failed")]
    Failed,
    /// The transaction succeeded but emitted no event that pays this quote.
    #[error("the transaction did not pay this quote")]
    NoMatchingPayment,
    /// The full node could not be asked, or the nodes disagree.
    #[error("the full node could not be asked: {0}")]
    Rpc(anyhow::Error),
}

impl VerifyError {
    /// Whether asking again later can change the answer: the transaction is not known yet, or a node was unreachable.
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
    /// The nodes asked, in order; a payment counts only when all agree.
    nodes: Vec<GrpcWeb<T>>,
}

impl Sui<HttpTransport> {
    /// Open a client for each full node URL; at least one is required.
    pub fn new(fullnode_urls: &[String], timeout: Duration) -> anyhow::Result<Self> {
        // Without a node there is nothing to verify against: refuse to start.
        anyhow::ensure!(!fullnode_urls.is_empty(), "at least one full node");
        // One transport and client per node, so each is asked separately.
        let nodes = fullnode_urls
            .iter()
            .map(|u| Ok(GrpcWeb::new(HttpTransport::new(timeout)?, u.clone())))
            .collect::<anyhow::Result<_>>()?;
        Ok(Self { nodes })
    }
}

impl<T: Transport> Sui<T> {
    /// A single-node client over a given transport (tests use a scripted one).
    pub fn with_transport(transport: T, fullnode_url: &str) -> Self {
        Self { nodes: vec![GrpcWeb::new(transport, fullnode_url.to_string())] }
    }

    /// A client over several nodes with their transports.
    pub fn with_transports(nodes: Vec<(T, String)>) -> Self {
        Self { nodes: nodes.into_iter().map(|(t, u)| GrpcWeb::new(t, u)).collect() }
    }

    /// Ask every node about the transaction and combine the answers with [`agree`]; a digest that is not well formed never reaches the network.
    pub async fn verify_payment(&self, digest: &str, expected: &Expected<'_>) -> Result<Confirmed, VerifyError> {
        // A malformed digest is not a payment; it never reaches the network.
        if !is_digest(digest) {
            return Err(VerifyError::NoMatchingPayment);
        }
        // Every node is asked, so one wrong or lying node cannot decide alone.
        let mut answers = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            answers.push(Self::ask(node, digest, expected).await);
        }
        agree(answers)
    }

    /// A merchant object's governance state as every configured node reports it. Nodes that disagree are an error (the
    /// caller treats an unknown state as a reason to stop quoting).
    pub async fn merchant_state(&self, object_id: &str) -> anyhow::Result<MerchantState> {
        let mut mask = ProtoWriter::new();
        // Ask the node for the object's JSON only.
        mask.string_field(FIELDMASK_PATHS, "json");
        // The request: the object id and the field mask.
        let mut req = ProtoWriter::new();
        req.string_field(GO_OBJECT_ID, object_id);
        req.bytes_field(GO_READ_MASK, &mask.into_bytes());
        let req = req.into_bytes();
        let mut seen: Option<MerchantState> = None;
        for node in &self.nodes {
            let resp = node.call(LEDGER_GET_OBJECT, req.clone()).await?;
            let state = field_bytes(&resp, GO_OBJECT)
                .and_then(|o| field_bytes(o, OBJECT_JSON))
                .and_then(parse_merchant)
                .ok_or_else(|| anyhow::anyhow!("{object_id} is not a readable merchant object"))?;
            // Every node must report the same governance state, or the state is unknown.
            match &seen {
                Some(s) if *s != state => anyhow::bail!("the full nodes disagree about merchant {object_id}"),
                _ => seen = Some(state),
            }
        }
        seen.ok_or_else(|| anyhow::anyhow!("no full node configured"))
    }

    /// Ask one node: not found is a retry, any other failure of the call is an RPC problem, otherwise check the answer against the quote.
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
    // No answers at all is a failure to ask, not a rejection.
    let Some(first) = answers.next() else { return Err(VerifyError::Rpc(anyhow::anyhow!("no full node configured"))) };
    let rest: Vec<_> = answers.collect();
    // One node: its answer stands.
    if rest.is_empty() {
        return first;
    }
    let all = std::iter::once(&first).chain(rest.iter());
    // Any node that could not be asked makes the whole answer "retry later".
    if let Some(Err(VerifyError::Rpc(e))) = all.clone().find(|a| matches!(a, Err(VerifyError::Rpc(_)))) {
        return Err(VerifyError::Rpc(anyhow::anyhow!("a full node could not be asked: {e}")));
    }
    let confirmed: Vec<&Confirmed> = all.clone().filter_map(|a| a.as_ref().ok()).collect();
    if !confirmed.is_empty() {
        // All nodes confirmed the same payment: confirmed.
        if confirmed.len() == rest.len() + 1 && confirmed.iter().all(|c| *c == confirmed[0]) {
            return first;
        }
        if all.clone().any(|a| matches!(a, Err(VerifyError::NotFound))) && confirmed.iter().all(|c| *c == confirmed[0])
        {
            return Err(VerifyError::NotFound);
        }
        // A confirmation next to anything else is a disagreement, never a confirmation.
        return Err(VerifyError::Rpc(anyhow::anyhow!("the full nodes disagree about this transaction")));
    }
    // "Not known yet" on any node: look again later.
    if all.clone().any(|a| matches!(a, Err(VerifyError::NotFound))) {
        return Err(VerifyError::NotFound);
    }
    // A rejection stands only when every node gives the same one.
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

/// An address in the full-node form (lowercase, 64 hex digits).
pub fn normalize(address: &str) -> String {
    normalize_address(address)
}

/// A merchant's governance fields, as the package stores them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerchantState {
    /// The address payments go to.
    pub recipient: String,
    /// A recipient change that is waiting to take effect, if any.
    pub pending_recipient: Option<String>,
    /// The quote key, lowercase hex.
    pub quote_key: String,
    /// Whether the merchant object is paused.
    pub paused: bool,
}

/// The string of a `google.protobuf.Value` (field 3), if it holds one.
fn value_string(v: &[u8]) -> Option<String> {
    field_str(v, 3).map(str::to_string)
}

/// Reads a `Merchant` object's JSON (a `google.protobuf.Value`): its own top-level fields only.
pub fn parse_merchant(json: &[u8]) -> Option<MerchantState> {
    // The recipient, in the full-node form so it compares exactly.
    let recipient = normalize_address(&value_string(value_field(json, "recipient")?)?);
    // The quote key is 32 bytes (an ed25519 public key), base64 in the JSON.
    let quote_key = b64(&value_string(value_field(json, "quote_key")?)?).filter(|k| k.len() == 32)?;
    let paused = value_as_bool(value_field(json, "paused")?)?;
    // An Option is null (absent struct) or the struct itself.
    let pending_recipient = value_field(json, "pending_recipient")
        .and_then(|p| value_field(p, "recipient"))
        .and_then(value_string)
        .map(|r| normalize_address(&r));
    Some(MerchantState {
        recipient,
        pending_recipient,
        quote_key: quote_key.iter().map(|b| format!("{b:02x}")).collect(),
        paused,
    })
}

/// One `Paid` event found through GraphQL: a candidate claim, still verified through the full nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidEvent {
    /// The transaction digest.
    pub digest: String,
    /// The quote nonce, decoded from the event.
    pub nonce: String,
}

/// A page of a package's `Paid` events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidPage {
    /// The events on the page, in the order the node returned them.
    pub events: Vec<PaidEvent>,
    /// Where to continue after this page.
    pub end_cursor: Option<String>,
    /// Whether the node has more.
    pub has_next: bool,
}

/// The GraphQL query: the package's `Paid` events, 50 at a time, with each event's transaction digest and decoded JSON.
const PAID_EVENTS_QUERY: &str = "query($t:String!,$after:String){events(first:50,after:$after,filter:{type:$t}){pageInfo{hasNextPage endCursor}nodes{transaction{digest}contents{json}}}}";

/// Reads a page of `<package>::chain_payments::Paid` events after `after` from a Sui GraphQL endpoint.
pub async fn paid_events(
    client: &reqwest::Client,
    url: &str,
    package_id: &str,
    after: Option<&str>,
) -> anyhow::Result<PaidPage> {
    let body = serde_json::json!({
        "query": PAID_EVENTS_QUERY,
        "variables": { "t": format!("{package_id}::chain_payments::Paid"), "after": after },
    });
    // The error text of a failed request would name the URL, which can carry a credential: it is dropped (CONF lens).
    let resp = client.post(url).json(&body).send().await.map_err(reqwest::Error::without_url)?;
    // A non-2xx answer is an error with its status code only.
    anyhow::ensure!(resp.status().is_success(), "GraphQL HTTP {}", resp.status());
    let v: serde_json::Value = resp.json().await.map_err(reqwest::Error::without_url)?;
    parse_paid_page(&v)
}

/// Parses a GraphQL answer to [`paid_events`]. Events whose digest or nonce cannot be read are skipped (they cannot be
/// one of our quotes); a GraphQL error is an error.
pub fn parse_paid_page(v: &serde_json::Value) -> anyhow::Result<PaidPage> {
    if let Some(e) = v.get("errors").and_then(|e| e.as_array()).filter(|e| !e.is_empty()) {
        anyhow::bail!("GraphQL: {}", e[0]["message"].as_str().unwrap_or("error"));
    }
    // The page of events inside the GraphQL envelope.
    let ev = &v["data"]["events"];
    anyhow::ensure!(ev.is_object(), "GraphQL: no events in the answer");
    let events = ev["nodes"]
        .as_array()
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| {
                    // Skip an event whose digest or nonce is unreadable: it cannot be one of our quotes.
                    let digest = n["transaction"]["digest"].as_str().filter(|d| is_digest(d))?.to_string();
                    let nonce = n["contents"]["json"]["nonce"].as_str().and_then(b64)?;
                    let nonce = String::from_utf8(nonce).ok().filter(|s| s.len() == 32)?;
                    Some(PaidEvent { digest, nonce })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(PaidPage {
        events,
        end_cursor: ev["pageInfo"]["endCursor"].as_str().map(str::to_string),
        has_next: ev["pageInfo"]["hasNextPage"].as_bool().unwrap_or(false),
    })
}

/// Decode base64, or `None` when it is not.
fn b64(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}

/// A decimal u64 from the event JSON, with a length bound so a long string is never parsed.
fn u64_field(json: &[u8], key: &str) -> Option<u64> {
    value_find_string(json, key)
        .filter(|s| s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
}

/// Checks a `GetTransactionResponse` (status and events) against what the quote expects.
pub fn check_response(resp: &[u8], expected: &Expected<'_>) -> Result<Confirmed, VerifyError> {
    // No transaction in the answer means the node does not know it.
    let tx = field_bytes(resp, RESP_TRANSACTION).ok_or(VerifyError::NotFound)?;
    // A failed transaction paid nothing, whatever events it emitted.
    if !effects_succeeded(tx) {
        return Err(VerifyError::Failed);
    }
    // The event type of this package, in the node's form.
    let want_type = normalize_move_type(&format!("{}::chain_payments::Paid", expected.package_id));
    let merchant = normalize_address(expected.merchant_object);
    // A transaction with no events paid nothing.
    let events = field_bytes(tx, EXECUTED_EVENTS).ok_or(VerifyError::NoMatchingPayment)?;
    // Walk the transaction's events; only one that matches every quote field counts.
    for f in ProtoReader::new(events) {
        let Field::Len(EVENTS_EVENTS, ev) = f else { continue };
        if !field_str(ev, EVENT_TYPE).is_some_and(|t| normalize_move_type(t) == want_type) {
            continue;
        }
        let Some(json) = field_bytes(ev, EVENT_JSON) else { continue };
        // Compare every field the quote signed against the event: merchant, session, nonce, coin type, amount, units and reference.
        let matches = value_find_string(json, "merchant_id").is_some_and(|m| normalize_address(&m) == merchant)
            && value_find_string(json, "session").and_then(|s| b64(&s)).as_deref() == Some(expected.session.as_bytes())
            && value_find_string(json, "nonce").and_then(|s| b64(&s)).as_deref() == Some(expected.nonce.as_bytes())
            && value_find_string(json, "coin_type").as_deref() == Some(expected.coin_type)
            && u64_field(json, "amount") == Some(expected.amount)
            // Units are compared too, so a quote signed with a stolen key cannot buy more than the session sold.
            && u64_field(json, "units") == Some(expected.units)
            && match value_find_string(json, "subscription_ref") {
                Some(r) => b64(&r).as_deref() == Some(expected.subscription_ref.as_bytes()),
                // The package's event always has the field; an empty vector may be rendered as an absent value.
                None => expected.subscription_ref.is_empty(),
            };
        if !matches {
            continue;
        }
        // The payer from the event, else the transaction sender.
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

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// A failed request to a full node or the GraphQL endpoint never repeats the URL it was sent to: a configured URL can carry a user name,
    /// password, path token or query key, and the error text is logged and stored with the payment.
    #[tokio::test]
    async fn a_failed_request_never_repeats_the_url() {
        let url = "https://user:s3cret@127.0.0.1:9/tok3n?key=k3y";
        let transport = HttpTransport::new(Duration::from_secs(2)).unwrap();
        let e = transport.post_grpc_web(url, vec![]).await.unwrap_err().to_string();
        let g = paid_events(&reqwest::Client::new(), url, "0x1", None).await.unwrap_err().to_string();
        for text in [e, g] {
            for part in ["user", "s3cret", "tok3n", "k3y", "127.0.0.1"] {
                assert!(!text.contains(part), "{text:?} repeats {part}");
            }
        }
    }

    /// A confirmed answer for the given payer.
    fn ok(payer: &str) -> Result<Confirmed, VerifyError> {
        Ok(Confirmed { payer: payer.into(), amount: 5, units: 1, paid_until_ms: 9, platform_fee: 0 })
    }

    /// A `google.protobuf.Value` holding a string.
    fn value_str(s: &str) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.string_field(3, s);
        w.into_bytes()
    }
    /// A `Value` holding a boolean.
    fn value_bool(b: bool) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.uint_field(4, b as u64);
        w.into_bytes()
    }
    /// A `Value` holding null.
    fn value_null() -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.uint_field(1, 0);
        w.into_bytes()
    }
    /// A `Value` holding a struct of the given fields.
    fn value_struct(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut st = ProtoWriter::new();
        for (k, v) in fields {
            let mut e = ProtoWriter::new();
            e.string_field(1, k);
            e.bytes_field(2, v);
            st.bytes_field(1, &e.into_bytes());
        }
        let mut w = ProtoWriter::new();
        w.bytes_field(5, &st.into_bytes());
        w.into_bytes()
    }

    /// Merchant objects are read by their own fields.
    #[test]
    fn merchant_objects_are_read_by_their_own_fields() {
        let key = STANDARD.encode([7u8; 32]);
        let pending = value_struct(&[("recipient", value_str("0xBEEF")), ("effective_ms", value_str("5"))]);
        let json = value_struct(&[
            ("pending_recipient", pending),
            ("recipient", value_str("0x00a1")),
            ("quote_key", value_str(&key)),
            ("paused", value_bool(false)),
        ]);
        let m = parse_merchant(&json).unwrap();
        assert_eq!(m.recipient, normalize_address("0xa1"), "the merchant's own recipient, not the pending one");
        assert_eq!(m.pending_recipient, Some(normalize_address("0xbeef")));
        assert_eq!(m.quote_key, "07".repeat(32));
        assert!(!m.paused);
        let none = value_struct(&[
            ("pending_recipient", value_null()),
            ("recipient", value_str("0xa1")),
            ("quote_key", value_str(&key)),
            ("paused", value_bool(true)),
        ]);
        let m = parse_merchant(&none).unwrap();
        assert_eq!((m.pending_recipient, m.paused), (None, true));
        assert!(parse_merchant(&value_struct(&[("recipient", value_str("0xa1"))])).is_none(), "fields missing");
    }

    /// Paid events from graphql.
    #[test]
    fn paid_events_from_graphql() {
        // The shape testnet's GraphQL returned on 2026-11-17 for the live payment.
        let v = serde_json::json!({"data":{"events":{"pageInfo":{"hasNextPage":true,"endCursor":"CUR"},"nodes":[
            {"transaction":{"digest":"33nefFTR2NG3LcCYzpnRjEsvu6gBTNhgMeDc9EyCqvFa"},
             "contents":{"json":{"nonce":"ZmFlZmVjOGMwNWFiYjMwMjA5YWM0ZmYzNzM0NjkyODI=","amount":"17971067"}}},
            {"transaction":{"digest":"not a digest"},"contents":{"json":{"nonce":"eA=="}}}
        ]}}});
        let p = parse_paid_page(&v).unwrap();
        assert_eq!(
            p.events,
            vec![PaidEvent {
                digest: "33nefFTR2NG3LcCYzpnRjEsvu6gBTNhgMeDc9EyCqvFa".into(),
                nonce: "faefec8c05abb30209ac4ff373469282".into(),
            }]
        );
        assert_eq!((p.end_cursor.as_deref(), p.has_next), (Some("CUR"), true));
        assert!(parse_paid_page(&serde_json::json!({"errors":[{"message":"bad"}]})).is_err());
    }

    /// Nodes must agree.
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
    /// A fixture package id.
    const PKG: &str = "0x5f67109c6b436fc0c0415d7f3e63ca10d374d8c4bb5e3b1f087cabb1c785bc14";
    /// A fixture merchant object id.
    const MERCHANT: &str = "0x30b6d544652d35d4a481fa7e45adf8e514b9ae1596377e837b6fdf36d967dae8";
    /// The canonical SUI coin type.
    const SUI: &str = "0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
    /// A fixture transaction digest.
    const DIGEST: &str = "7AkSLeZfxX2qURL2oHYmKkf3AKNaunJBJLski7TzGUYR";

    /// What the fixture payment must match.
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

    /// Recorded payment is confirmed and any difference is not.
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

    /// Digests.
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
        // Merchant #1 of the current testnet package (deployments.json): its live governance fields.
        let m = sui.merchant_state("0x1015d740c7f4261bae407bf62559eea4e6f76a97377c7149febf49ac9520d814").await.unwrap();
        assert_eq!(m.recipient, "0xa991ae11b0785718cd3ad1c616e804a4c083f431b3144bb845bdec651164864a");
        assert_eq!(m.quote_key, "c80751d89f3e5391037039de90118c553e7b3f00109c71badd33cc4910482e8c");
        assert_eq!((m.pending_recipient, m.paused), (None, false));
    }
}
