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
use chain_payments_core::money::format_gbp;
use chain_payments_core::session::{DEFAULT_SESSION_SECS, NewSession, random_id};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::{App, OpError, Shared};
use crate::metrics::Metrics;

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

impl IntoResponse for OpError {
    fn into_response(self) -> Response {
        match self {
            OpError::NotFound => error(StatusCode::NOT_FOUND, "not found"),
            OpError::Refused(m) => error(StatusCode::CONFLICT, &m),
            OpError::NoPrice => error(StatusCode::SERVICE_UNAVAILABLE, &self.to_string()),
            OpError::Store(e) => {
                tracing::error!(error = %e, "storage");
                error(StatusCode::SERVICE_UNAVAILABLE, "storage is unavailable")
            }
        }
    }
}

fn valid_session_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ── public ───────────────────────────────────────────────────────────────────

async fn get_session(State(app): State<Shared>, Path(id): Path<String>) -> Result<Response, OpError> {
    if !valid_session_id(&id) {
        return Err(OpError::NotFound);
    }
    let s = app.store.session(&id).await?.ok_or(OpError::NotFound)?;
    let open = s.status == "open" && s.expires_at > Utc::now();
    let methods: Vec<Value> = s.methods.iter().filter_map(|m| app.method(m)).map(App::method_json).collect();
    Ok(Json(json!({
        "id": s.id,
        "status": if s.status == "open" && !open { "expired" } else { s.status.as_str() },
        "amountPence": s.amount_pence,
        "amountText": format_gbp(s.amount_pence as u64),
        "description": s.description,
        "units": s.units,
        "expiresAt": s.expires_at.to_rfc3339(),
        "methods": methods,
    }))
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuoteRequest {
    method: String,
}

async fn post_quote(
    State(app): State<Shared>,
    Path(id): Path<String>,
    Json(r): Json<QuoteRequest>,
) -> Result<Response, OpError> {
    if !valid_session_id(&id) || r.method.len() > 64 {
        return Err(OpError::NotFound);
    }
    Ok(Json(app.quote(&id, &r.method).await?).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentRequest {
    nonce: String,
    digest: String,
}

async fn post_payment(
    State(app): State<Shared>,
    Path(id): Path<String>,
    Json(r): Json<PaymentRequest>,
) -> Result<Response, OpError> {
    if !valid_session_id(&id) || !chain_payments_chain_sui::is_digest(&r.digest) || r.nonce.len() != 32 {
        return Err(OpError::Refused("not a valid payment".into()));
    }
    let q = app.store.quote(&r.nonce).await?.ok_or(OpError::NotFound)?;
    if q.session_id != id {
        return Err(OpError::NotFound);
    }
    app.store.submit_payment(&r.digest, &id, &r.nonce).await?;
    Metrics::inc(&app.metrics.payments_submitted);
    // One immediate check (the transaction is usually final already); the watcher retries a pending one.
    let status = app.settle(&r.digest).await?;
    Ok(Json(json!({ "digest": r.digest, "status": status })).into_response())
}

async fn get_payment(
    State(app): State<Shared>,
    Path((id, digest)): Path<(String, String)>,
) -> Result<Response, OpError> {
    let p = app.store.payment(&digest).await?.ok_or(OpError::NotFound)?;
    if p.session_id != id {
        return Err(OpError::NotFound);
    }
    Ok(Json(json!({ "digest": p.digest, "status": p.status })).into_response())
}

async fn webhook_key(State(app): State<Shared>) -> Response {
    Json(json!({ "algorithm": "ed25519", "publicKey": app.config.webhook_signer.public_hex(), "header": chain_payments_core::webhook::HEADER })).into_response()
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn readyz(State(app): State<Shared>) -> Response {
    match app.store.ping().await {
        Ok(()) => "ready\n".into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "storage is unavailable"),
    }
}

/// CORS for the configured checkout origins only; security headers on everything.
async fn public_guard(State(app): State<Shared>, req: Request<Body>, next: Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()).map(str::to_string);
    let allowed = origin.as_deref().filter(|o| app.config.allowed_origins.iter().any(|a| a == o)).map(str::to_string);
    let mut r = if req.method() == Method::OPTIONS {
        if allowed.is_some() { StatusCode::NO_CONTENT.into_response() } else { StatusCode::FORBIDDEN.into_response() }
    } else {
        next.run(req).await
    };
    let h = r.headers_mut();
    if let Some(o) = allowed.and_then(|o| HeaderValue::from_str(&o).ok()) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST"));
        h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("content-type"));
        h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
        h.insert(header::VARY, HeaderValue::from_static("origin"));
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"));
    h.remove(header::SET_COOKIE);
    r
}

pub fn public_router(app: Shared) -> Router {
    Router::new()
        .route("/v1/sessions/{id}", get(get_session))
        .route("/v1/sessions/{id}/quotes", post(post_quote))
        .route("/v1/sessions/{id}/payments", post(post_payment))
        .route("/v1/sessions/{id}/payments/{digest}", get(get_payment))
        .route("/v1/webhook-key", get(webhook_key))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .fallback(|| async { error(StatusCode::NOT_FOUND, "not found") })
        .layer(middleware::from_fn_with_state(app.clone(), public_guard))
        .layer(DefaultBodyLimit::max(4 * 1024))
        .with_state(app)
}

// ── merchant ─────────────────────────────────────────────────────────────────

async fn merchant_of(app: &App, headers: &HeaderMap) -> Result<chain_payments_store::Merchant, Box<Response>> {
    let key = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|k| k.len() >= 32 && k.len() <= 128);
    let Some(key) = key else { return Err(Box::new(error(StatusCode::UNAUTHORIZED, "an API key is required"))) };
    match app.store.merchant_by_key(key).await {
        Ok(Some(m)) => Ok(m),
        Ok(None) => Err(Box::new(error(StatusCode::UNAUTHORIZED, "unknown API key"))),
        Err(e) => Err(Box::new(OpError::Store(e).into_response())),
    }
}

async fn create_session(State(app): State<Shared>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    // Authenticate before reading the body, so an unauthenticated caller learns nothing about the request format.
    let m = match merchant_of(&app, &headers).await {
        Ok(m) => m,
        Err(r) => return *r,
    };
    let n: NewSession = match serde_json::from_slice(&body) {
        Ok(n) => n,
        Err(e) => return error(StatusCode::UNPROCESSABLE_ENTITY, &format!("not a valid session request: {e}")),
    };
    if let Err(e) = n.check() {
        return error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
    }
    let methods: Vec<String> = if n.methods.is_empty() {
        m.methods.clone()
    } else {
        n.methods.iter().filter(|x| m.methods.contains(x)).cloned().collect()
    };
    if methods.is_empty() || methods.iter().any(|x| app.method(x).is_none()) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "no enabled payment method");
    }
    let id = random_id(16);
    let expires = Utc::now() + chrono::Duration::seconds(n.expires_in_secs.unwrap_or(DEFAULT_SESSION_SECS) as i64);
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
            (StatusCode::CREATED, Json(json!({ "id": id, "expiresAt": expires.to_rfc3339(), "methods": methods })))
                .into_response()
        }
        Err(e) => OpError::Store(e).into_response(),
    }
}

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
    let payments = app.store.session_payments(&id).await.unwrap_or_default();
    Json(json!({
        "id": s.id, "status": s.status, "amountPence": s.amount_pence, "units": s.units,
        "subscriptionRef": s.subscription_ref, "metadata": s.metadata, "expiresAt": s.expires_at.to_rfc3339(),
        "paidAt": s.paid_at.map(|t| t.to_rfc3339()),
        "payments": payments.iter().map(|p| json!({ "digest": p.digest, "status": p.status, "payer": p.payer, "paidUntilMs": p.paid_until_ms })).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn cancel_session(State(app): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let m = match merchant_of(&app, &headers).await {
        Ok(m) => m,
        Err(r) => return *r,
    };
    match app.store.cancel_session(m.id, &id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(StatusCode::CONFLICT, "not an open session of yours"),
        Err(e) => OpError::Store(e).into_response(),
    }
}

async fn metrics(State(app): State<Shared>) -> Response {
    let backlog = app.store.backlog().await.ok();
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], app.metrics.render(backlog)).into_response()
}

pub fn merchant_router(app: Shared) -> Router {
    Router::new()
        .route("/v1/merchant/sessions", post(create_session))
        .route("/v1/merchant/sessions/{id}", get(merchant_session))
        .route("/v1/merchant/sessions/{id}/cancel", post(cancel_session))
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(app)
}

/// The worker's own port: its counters (confirmations, webhook deliveries) live in its process, so it serves them itself.
pub fn worker_router(app: Shared) -> Router {
    Router::new().route("/metrics", get(metrics)).route("/healthz", get(healthz)).with_state(app)
}
