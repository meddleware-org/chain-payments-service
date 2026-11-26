//! The two routers. **Public** (port 8080, the only one behind the Ingress): a checkout reads its session, asks for a
//! quote and submits the transaction digest; nothing here needs a secret, and a session id is an unguessable capability.
//! **Merchant** (port 8081, cluster-internal): create, read and cancel sessions with an API key; metrics.

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use std::time::Duration;

use chain_payments_core::money::format_gbp;
use chain_payments_core::session::{DEFAULT_SESSION_SECS, NewSession, random_id};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::app::{App, OpError, Shared};
use crate::metrics::Metrics;

/// Requests one API process works on at once. Bodies are capped at 4 KiB (public) and 16 KiB (merchant), so the memory
/// they can hold is well under a megabyte; the real bound is the database pool and the full node, which queue behind it.
pub const MAX_CONCURRENT_REQUESTS: usize = 64;
/// Longest a request may take: a quote waits for the price sources (6 s) and a payment for the full node (10 s).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A JSON error answer: `{ "error": message }` with the status.
fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

impl IntoResponse for OpError {
    /// Map an operation error to its HTTP status; a storage failure is logged and answered generically.
    fn into_response(self) -> Response {
        match self {
            OpError::NotFound => error(StatusCode::NOT_FOUND, "not found"),
            OpError::Refused(m) => error(StatusCode::CONFLICT, &m),
            OpError::NoPrice => error(StatusCode::SERVICE_UNAVAILABLE, &self.to_string()),
            OpError::TooManyClaims => error(StatusCode::TOO_MANY_REQUESTS, &self.to_string()),
            OpError::Store(e) => {
                tracing::error!(error = %e, "storage");
                error(StatusCode::SERVICE_UNAVAILABLE, "storage is unavailable")
            }
        }
    }
}

/// A session id is exactly 32 lower-case hex digits; anything else is not found before it reaches the database.
fn valid_session_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ── public ───────────────────────────────────────────────────────────────────

/// The checkout reads its session: status, amount, description and the methods it may use.
async fn get_session(State(app): State<Shared>, Path(id): Path<String>) -> Result<Response, OpError> {
    if !valid_session_id(&id) {
        return Err(OpError::NotFound);
    }
    // An unknown session is a 404 whatever the reason.
    let s = app.store.session(&id).await?.ok_or(OpError::NotFound)?;
    // A session whose time has passed reads as expired even before the worker marks it.
    let open = s.status == "open" && s.expires_at > OffsetDateTime::now_utc();
    // Only methods the registry still knows are shown.
    let methods: Vec<Value> = s.methods.iter().filter_map(|m| app.method(m)).map(App::method_json).collect();
    Ok(Json(json!({
        "id": s.id,
        "status": if s.status == "open" && !open { "expired" } else { s.status.as_str() },
        "amountPence": s.amount_pence,
        "amountText": format_gbp(s.amount_pence as u64),
        "description": s.description,
        "units": s.units,
        "expiresAt": crate::rfc3339(s.expires_at),
        "methods": methods,
    }))
    .into_response())
}

/// The body of a quote request: the method id.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuoteRequest {
    /// The payment method the buyer chose.
    method: String,
}

/// Sign a quote for a session and method.
async fn post_quote(
    State(app): State<Shared>,
    Path(id): Path<String>,
    Json(r): Json<QuoteRequest>,
) -> Result<Response, OpError> {
    // Cheap checks first: a malformed id or an over-long method never reaches the database.
    if !valid_session_id(&id) || r.method.len() > 64 {
        return Err(OpError::NotFound);
    }
    // The operation does the checks; the router only maps its result to HTTP.
    Ok(Json(app.quote(&id, &r.method).await?).into_response())
}

/// The body of a payment submission.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentRequest {
    /// The nonce of the quote the transaction pays.
    nonce: String,
    /// The digest of the transaction the buyer sent.
    digest: String,
}

/// Claims a session may have waiting for the chain at once (a real payment is usually final within seconds).
pub const MAX_PENDING_CLAIMS: i64 = 5;

/// Record a claim that a transaction paid a quote, check it once now, and cap the claims waiting for the chain.
async fn post_payment(
    State(app): State<Shared>,
    Path(id): Path<String>,
    Json(r): Json<PaymentRequest>,
) -> Result<Response, OpError> {
    if !valid_session_id(&id) || !chain_payments_chain_sui::is_digest(&r.digest) || r.nonce.len() != 32 {
        return Err(OpError::Refused("not a valid payment".into()));
    }
    // The nonce must be one of our quotes, and must belong to this session.
    let q = app.store.quote(&r.nonce).await?.ok_or(OpError::NotFound)?;
    if q.session_id != id {
        return Err(OpError::NotFound);
    }
    // Record the claim first: even if the check below fails, the watcher will retry it.
    let submitted = app.store.submit_payment(&r.digest, &id, &r.nonce).await?;
    Metrics::inc(&app.metrics.payments_submitted);
    // One immediate check (the transaction is usually final already); the watcher retries a pending one.
    // Settle once now so the checkout usually learns the result at once.
    let status = app.settle(&r.digest, &r.nonce).await?;
    // Anyone who knows a session id can post well-formed digests; each one the chain does not know yet is re-checked
    // for an hour. A new claim still pending beyond the cap is withdrawn, so they cannot pile up.
    if status == "pending"
        && submitted == chain_payments_store::Submitted::New
        && app.store.pending_claims(&id).await? > MAX_PENDING_CLAIMS
    {
        app.store.withdraw_pending_claim(&r.digest, &r.nonce).await?;
        return Err(OpError::TooManyClaims);
    }
    // The status is `pending` while the chain has not confirmed, so the checkout keeps following it.
    Ok(Json(json!({ "digest": r.digest, "status": status })).into_response())
}

/// The status of a payment, for a checkout that is following it.
async fn get_payment(
    State(app): State<Shared>,
    Path((id, digest)): Path<(String, String)>,
) -> Result<Response, OpError> {
    if !valid_session_id(&id) || !chain_payments_chain_sui::is_digest(&digest) {
        return Err(OpError::NotFound);
    }
    let status = app.store.session_payment_status(&id, &digest).await?.ok_or(OpError::NotFound)?;
    Ok(Json(json!({ "digest": digest, "status": status })).into_response())
}

/// The public key a merchant verifies webhook signatures with, and the header they arrive in.
async fn webhook_key(State(app): State<Shared>) -> Response {
    // Merchants verify webhooks with this public key; no shared secret exists.
    Json(json!({ "algorithm": "ed25519", "publicKey": app.config.webhook_public, "header": chain_payments_core::webhook::HEADER })).into_response()
}

/// Liveness: the process answers.
async fn healthz() -> &'static str {
    "ok\n"
}

/// Readiness: the database answers.
async fn readyz(State(app): State<Shared>) -> Response {
    match app.store.ping().await {
        Ok(()) => "ready\n".into_response(),
        // The cause is not sent: a readiness probe needs only up or down.
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "storage is unavailable"),
    }
}

/// CORS for the configured checkout origins only; security headers on everything.
async fn public_guard(State(app): State<Shared>, req: Request<Body>, next: Next) -> Response {
    // CORS: only the configured checkout origins are allowed; any other origin gets no CORS headers at all.
    let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()).map(str::to_string);
    // The origin must match a configured one exactly.
    let allowed = origin.as_deref().filter(|o| app.config.allowed_origins.iter().any(|a| a == o)).map(str::to_string);
    // A preflight is answered here, only for an allowed origin.
    let mut r = if req.method() == Method::OPTIONS {
        if allowed.is_some() { StatusCode::NO_CONTENT.into_response() } else { StatusCode::FORBIDDEN.into_response() }
    } else {
        next.run(req).await
    };
    // Headers are added to whatever the route answered, including errors.
    let h = r.headers_mut();
    if let Some(o) = allowed.and_then(|o| HeaderValue::from_str(&o).ok()) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST"));
        h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("content-type"));
        h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
        h.insert(header::VARY, HeaderValue::from_static("origin"));
    }
    // Nothing the service says is cached: every answer is about the moment it was asked.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    // A JSON API loads nothing and cannot be framed.
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"));
    // The service never sets a cookie (D134: nothing stored in a browser before an action).
    h.remove(header::SET_COOKIE);
    r
}

/// The public router: only the checkout routes, with CORS for the configured origins, a small body cap, a timeout and a process-wide concurrency limit.
pub fn public_router(app: Shared) -> Router {
    Router::new()
        // The checkout routes: read a session, ask for a quote, submit and follow a payment.
        .route("/v1/sessions/{id}", get(get_session))
        .route("/v1/sessions/{id}/quotes", post(post_quote))
        .route("/v1/sessions/{id}/payments", post(post_payment))
        .route("/v1/sessions/{id}/payments/{digest}", get(get_payment))
        // The webhook public key is public: merchants fetch it once and pin it.
        .route("/v1/webhook-key", get(webhook_key))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // Anything else is a JSON 404, not an HTML page.
        .fallback(|| async { error(StatusCode::NOT_FOUND, "not found") })
        // CORS and the security headers wrap every public route.
        .layer(middleware::from_fn_with_state(app.clone(), public_guard))
        // Public bodies are tiny (a method id or a digest), so 4 KiB is generous.
        .layer(DefaultBodyLimit::max(4 * 1024))
        // A request that takes longer than thirty seconds is answered 408.
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT))
        // One limit for the whole router, not one per route.
        .layer(per_process_limit(MAX_CONCURRENT_REQUESTS))
        .with_state(app)
}

/// One request limit for every route of a router. `Router::layer` wraps each route separately, and
/// `ConcurrencyLimitLayer` makes a new semaphore each time it wraps, so it would allow `max` per route. The global layer
/// shares one semaphore across every route.
pub(crate) fn per_process_limit(max: usize) -> GlobalConcurrencyLimitLayer {
    GlobalConcurrencyLimitLayer::new(max)
}

// ── merchant ─────────────────────────────────────────────────────────────────

/// Authenticate a merchant by the bearer API key; the answer for a missing or unknown key is a ready 401.
async fn merchant_of(app: &App, headers: &HeaderMap) -> Result<chain_payments_store::Merchant, Box<Response>> {
    let key = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        // A key outside the length bounds is refused without a database lookup.
        .filter(|k| k.len() >= 32 && k.len() <= 128);
    // No key: the answer does not say whether a key would have worked.
    let Some(key) = key else { return Err(Box::new(error(StatusCode::UNAUTHORIZED, "an API key is required"))) };
    match app.store.merchant_by_key(key).await {
        Ok(Some(m)) => Ok(m),
        Ok(None) => Err(Box::new(error(StatusCode::UNAUTHORIZED, "unknown API key"))),
        Err(e) => Err(Box::new(OpError::Store(e).into_response())),
    }
}

/// Create a session for the authenticated merchant: validate the request, intersect the methods, store it.
async fn create_session(State(app): State<Shared>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    // Authenticate before reading the body, so an unauthenticated caller learns nothing about the request format.
    let m = match merchant_of(&app, &headers).await {
        Ok(m) => m,
        Err(r) => return *r,
    };
    // Parse only after authentication; unknown fields are refused by the type.
    let n: NewSession = match serde_json::from_slice(&body) {
        Ok(n) => n,
        Err(e) => return error(StatusCode::UNPROCESSABLE_ENTITY, &format!("not a valid session request: {e}")),
    };
    if let Err(e) = n.check() {
        return error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
    }
    // The session offers the methods the merchant enabled, narrowed to the ones the request names.
    let methods: Vec<String> = if n.methods.is_empty() {
        m.methods.clone()
    } else {
        n.methods.iter().filter(|x| m.methods.contains(x)).cloned().collect()
    };
    // The session must offer at least one method, and every one must exist in the registry.
    if methods.is_empty() || methods.iter().any(|x| app.method(x).is_none()) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "no enabled payment method");
    }
    // A random 128-bit id: the unguessable capability the checkout holds.
    let id = random_id(16);
    let expires =
        OffsetDateTime::now_utc() + time::Duration::seconds(n.expires_in_secs.unwrap_or(DEFAULT_SESSION_SECS) as i64);
    let r = app
        .store
        .create_session(
            &id,
            m.id,
            n.amount_pence as i64,
            n.description.trim(),
            n.units as i64,
            &n.subscription_ref,
            n.period_ms as i64,
            &methods,
            &n.metadata,
            expires,
        )
        .await;
    match r {
        Ok(()) => {
            Metrics::inc(&app.metrics.sessions_created);
            (StatusCode::CREATED, Json(json!({ "id": id, "expiresAt": crate::rfc3339(expires), "methods": methods })))
                .into_response()
        }
        Err(e) => OpError::Store(e).into_response(),
    }
}

/// A merchant reads one of its own sessions with its payments; a session of another merchant is not found.
async fn merchant_session(State(app): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let m = match merchant_of(&app, &headers).await {
        Ok(m) => m,
        Err(r) => return *r,
    };
    let s = match app.store.session(&id).await {
        Ok(Some(s)) if s.merchant_id == m.id => s,
        Ok(_) => return error(StatusCode::NOT_FOUND, "not found"),
        Err(e) => return OpError::Store(e).into_response(),
    };
    // A merchant sees the claims on its session; a read failure shows none rather than failing the read.
    let payments = app.store.session_payments(&id).await.unwrap_or_default();
    Json(json!({
        "id": s.id, "status": s.status, "amountPence": s.amount_pence, "units": s.units,
        "subscriptionRef": s.subscription_ref, "metadata": s.metadata, "expiresAt": crate::rfc3339(s.expires_at),
        "paidAt": s.paid_at.map(crate::rfc3339),
        "payments": payments.iter().map(|p| json!({ "digest": p.digest, "status": p.status, "payer": p.payer, "paidUntilMs": p.paid_until_ms })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Cancel an open session of the merchant.
async fn cancel_session(State(app): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let m = match merchant_of(&app, &headers).await {
        Ok(m) => m,
        Err(r) => return *r,
    };
    match app.store.cancel_session(m.id, &id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        // The same answer whether the session is not open or not yours.
        Ok(false) => error(StatusCode::CONFLICT, "not an open session of yours"),
        Err(e) => OpError::Store(e).into_response(),
    }
}

/// Prometheus text: the counters, the backlog and the merchant watch flags.
async fn metrics(State(app): State<Shared>) -> Response {
    // The backlog gauges are skipped when the database cannot be read.
    let backlog = app.store.backlog().await.ok();
    let mut body = app.metrics.render(backlog);
    if let Ok(rows) = app.store.merchant_watch_flags().await {
        body.push_str(&crate::metrics::Metrics::render_watch(&rows));
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

/// The merchant router (cluster-internal): sessions, metrics and health, with a larger body cap.
pub fn merchant_router(app: Shared) -> Router {
    Router::new()
        .route("/v1/merchant/sessions", post(create_session))
        .route("/v1/merchant/sessions/{id}", get(merchant_session))
        .route("/v1/merchant/sessions/{id}/cancel", post(cancel_session))
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        // Merchant bodies are larger (metadata up to 4 KiB), so the cap is 16 KiB.
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT))
        .layer(per_process_limit(MAX_CONCURRENT_REQUESTS))
        .with_state(app)
}

/// The worker's own port: its counters (confirmations, webhook deliveries) live in its process, so it serves them itself.
pub fn worker_router(app: Shared) -> Router {
    Router::new().route("/metrics", get(metrics)).route("/healthz", get(healthz)).with_state(app)
}

/// Tests for the process-wide request limit.
#[cfg(test)]
mod limit_tests {
    use std::time::{Duration, Instant};

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    /// A handler that takes 200 ms, to make the limit visible.
    async fn slow() -> StatusCode {
        tokio::time::sleep(Duration::from_millis(200)).await;
        StatusCode::OK
    }

    /// The limit is shared by every route.
    #[tokio::test]
    async fn the_limit_is_shared_by_every_route() {
        let r: Router = Router::new().route("/a", get(slow)).route("/b", get(slow)).layer(super::per_process_limit(1));
        let started = Instant::now();
        let (a, b) = tokio::join!(
            r.clone().oneshot(Request::get("/a").body(Body::empty()).unwrap()),
            r.clone().oneshot(Request::get("/b").body(Body::empty()).unwrap()),
        );
        assert_eq!(a.unwrap().status(), StatusCode::OK);
        assert_eq!(b.unwrap().status(), StatusCode::OK);
        assert!(started.elapsed() >= Duration::from_millis(400), "two routes, one limit: they ran one after the other");
    }
}
