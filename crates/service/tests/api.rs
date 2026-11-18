//! The routers against a real PostgreSQL (scripts/test-postgres.sh). Uses a GBP-pegged test method, so quoting needs no
//! price source; the chain is never reached (payment submission is checked for validation only).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chain_payments_service::api::{merchant_router, public_router};
use chain_payments_service::app::App;
use chain_payments_service::config::Config;
use chain_payments_store::Store;
use chain_payments_store::config::{Access, DatabaseSettings};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const KEY: &str = "cpk_0123456789abcdef0123456789abcdef0123456789abcdef";

async fn app() -> Option<Arc<App>> {
    app_with("https://fullnode.testnet.sui.io:443").await
}

/// The app with its testnet full node at `grpc` (an unreachable address keeps every claim pending, offline).
async fn app_with(grpc: &str) -> Option<Arc<App>> {
    let grpc = grpc.to_string();
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        assert!(std::env::var("REQUIRE_TEST_DATABASE").as_deref() != Ok("1"), "TEST_DATABASE_URL is required");
        eprintln!("SKIPPED: no TEST_DATABASE_URL");
        return None;
    };
    let admin = DatabaseSettings::parse(&url, false).unwrap().lazy_pool(2, Access::ReadWrite).unwrap();
    let name = format!("cp_api_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.unwrap();
    let pool = DatabaseSettings::parse(&url.replacen("/postgres?", &format!("/{name}?"), 1), false)
        .unwrap()
        .lazy_pool(4, Access::ReadWrite)
        .unwrap();
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    store.create_merchant("Test", KEY, None, &["sui-testnet:GBPT".into()]).await.unwrap();
    let dir = std::env::temp_dir().join(format!("cp-api-{name}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("q.key"), [1u8; 32]).unwrap();
    std::fs::write(dir.join("w.key"), [2u8; 32]).unwrap();
    std::fs::write(
        dir.join("methods.json"),
        json!({"methods":[{"id":"sui-testnet:GBPT","chain":"sui","network":"testnet","coinType":"0x99::gbpt::GBPT","symbol":"GBPT",
          "decimals":6,"priceSymbol":"GBPT","gbpPegged":true,"packageId":"0x5f67","merchantObject":"0x30b6"}]})
        .to_string(),
    )
    .unwrap();
    let env = |k: &str| -> Option<String> {
        match k {
            "METHODS_FILE" => Some(dir.join("methods.json").display().to_string()),
            "QUOTE_KEY_FILE" => Some(dir.join("q.key").display().to_string()),
            "WEBHOOK_KEY_FILE" => Some(dir.join("w.key").display().to_string()),
            "SUI_GRPC_TESTNET" => Some(grpc.clone()),
            "ALLOWED_ORIGINS" => Some("https://app.example.org".into()),
            "MAX_QUOTES_PER_SESSION" => Some("2".into()),
            _ => None,
        }
    };
    Some(Arc::new(App::new(store, Config::from_env(env).unwrap()).unwrap()))
}

async fn call(router: axum::Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let r = router.oneshot(req).await.unwrap();
    let (parts, body) = r.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn post(uri: &str, body: Value, key: Option<&str>) -> Request<Body> {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(k) = key {
        b = b.header(header::AUTHORIZATION, format!("Bearer {k}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn merchant_api_needs_a_key_and_validates() {
    let Some(app) = app().await else { return };
    let m = merchant_router(app.clone());
    let body = json!({"amountPence": 300, "description": "1 month"});
    assert_eq!(call(m.clone(), post("/v1/merchant/sessions", body.clone(), None)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(m.clone(), post("/v1/merchant/sessions", body.clone(), Some(&KEY.replace('0', "1")))).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (st, _, _) =
        call(m.clone(), post("/v1/merchant/sessions", json!({"amountPence": 0, "description": "x"}), Some(KEY))).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    let (st, _, v) = call(m.clone(), post("/v1/merchant/sessions", body, Some(KEY))).await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(v["methods"][0], "sui-testnet:GBPT");
}

#[tokio::test]
async fn a_checkout_reads_its_session_and_gets_exact_quotes() {
    let Some(app) = app().await else { return };
    let m = merchant_router(app.clone());
    let p = public_router(app.clone());
    let (_, _, v) = call(
        m,
        post(
            "/v1/merchant/sessions",
            json!({"amountPence": 300, "description": "1 month", "metadata": {"secret": "x"}}),
            Some(KEY),
        ),
    )
    .await;
    let id = v["id"].as_str().unwrap().to_string();
    let (st, _, s) = call(p.clone(), Request::get(format!("/v1/sessions/{id}")).body(Body::empty()).unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(s["amountText"], "£3.00");
    assert!(s.get("metadata").is_none(), "the merchant's metadata is never public");
    let (st, _, q) =
        call(p.clone(), post(&format!("/v1/sessions/{id}/quotes"), json!({"method": "sui-testnet:GBPT"}), None)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(q["amount"], "3000000", "£3.00 of a GBP-pegged coin with 6 decimals");
    assert_eq!(q["signature"].as_str().unwrap().len(), 128);
    let (st, _, _) =
        call(p.clone(), post(&format!("/v1/sessions/{id}/quotes"), json!({"method": "sui-testnet:SUI"}), None)).await;
    assert_eq!(st, StatusCode::CONFLICT, "a method not offered");
    call(p.clone(), post(&format!("/v1/sessions/{id}/quotes"), json!({"method": "sui-testnet:GBPT"}), None)).await;
    let (st, _, _) =
        call(p.clone(), post(&format!("/v1/sessions/{id}/quotes"), json!({"method": "sui-testnet:GBPT"}), None)).await;
    assert_eq!(st, StatusCode::CONFLICT, "the quote limit per session");
    let (st, _, _) = call(
        p.clone(),
        post(&format!("/v1/sessions/{id}/payments"), json!({"nonce": "x", "digest": "not a digest"}), None),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let digest = "7AkSLeZfxX2qURL2oHYmKkf3AKNaunJBJLski7TzGUYR";
    let (st, _, _) =
        call(p.clone(), Request::get(format!("/v1/sessions/{id}/payments/{digest}")).body(Body::empty()).unwrap())
            .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "no claim of this digest for this session");
    let (st, _, _) =
        call(p.clone(), Request::get(format!("/v1/sessions/{id}/payments/not-a-digest")).body(Body::empty()).unwrap())
            .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) =
        call(p, Request::get("/v1/sessions/ffffffffffffffffffffffffffffffff").body(Body::empty()).unwrap()).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cors_only_for_configured_origins_and_no_cookies() {
    let Some(app) = app().await else { return };
    let p = public_router(app);
    let pre = |o: &str| Request::options("/v1/webhook-key").header(header::ORIGIN, o).body(Body::empty()).unwrap();
    let (st, h, _) = call(p.clone(), pre("https://app.example.org")).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://app.example.org");
    let (st, h, _) = call(p.clone(), pre("https://evil.example")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    let (_, h, v) = call(p, Request::get("/v1/webhook-key").body(Body::empty()).unwrap()).await;
    assert_eq!(v["algorithm"], "ed25519");
    assert!(h.get(header::SET_COOKIE).is_none());
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn unverifiable_claims_are_capped_per_session() {
    // Nothing answers at 127.0.0.1:9, so every claim stays pending (an outage is retried, never decided).
    let Some(app) = app_with("https://127.0.0.1:9").await else { return };
    let m = merchant_router(app.clone());
    let p = public_router(app.clone());
    let (_, _, v) =
        call(m, post("/v1/merchant/sessions", json!({"amountPence": 300, "description": "1 month"}), Some(KEY))).await;
    let id = v["id"].as_str().unwrap().to_string();
    let (_, _, q) =
        call(p.clone(), post(&format!("/v1/sessions/{id}/quotes"), json!({"method": "sui-testnet:GBPT"}), None)).await;
    let nonce = q["nonce"].as_str().unwrap().to_string();
    // Well-formed digests (43 base58 characters) that no transaction has.
    const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let digest = |i: u8| String::from_utf8(vec![B58[i as usize % B58.len()]; 43]).unwrap();
    let claim =
        |i: u8| post(&format!("/v1/sessions/{id}/payments"), json!({"nonce": nonce, "digest": digest(i)}), None);
    for i in 1..=chain_payments_service::api::MAX_PENDING_CLAIMS as u8 {
        let (st, _, r) = call(p.clone(), claim(i)).await;
        assert_eq!((st, r["status"].as_str()), (StatusCode::OK, Some("pending")), "claim {i}");
    }
    let (st, _, _) = call(p.clone(), claim(99)).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "one claim beyond the cap");
    assert!(app.store.payment(&digest(99), &nonce).await.unwrap().is_none(), "and it was withdrawn");
    // A claim already known is answered as before, not counted again.
    let (st, _, _) = call(p.clone(), claim(1)).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn a_merchant_changed_on_chain_gets_no_quotes() {
    let Some(app) = app().await else { return };
    let m = merchant_router(app.clone());
    let p = public_router(app.clone());
    let (_, _, v) =
        call(m, post("/v1/merchant/sessions", json!({"amountPence": 300, "description": "1 month"}), Some(KEY))).await;
    let id = v["id"].as_str().unwrap().to_string();
    let quote = || post(&format!("/v1/sessions/{id}/quotes"), json!({"method": "sui-testnet:GBPT"}), None);
    // The worker read a pending recipient on the merchant object: quoting stops.
    app.store
        .record_merchant_watch(
            "0x30b6",
            "0xa1",
            Some("0xbeef"),
            "aa",
            false,
            false,
            false,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    let (st, _, e) = call(p.clone(), quote()).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(e["error"].as_str().unwrap().contains("pending"), "{e}");
    // Back to normal: quotes again.
    app.store
        .record_merchant_watch("0x30b6", "0xa1", None, "aa", false, false, false, time::OffsetDateTime::now_utc())
        .await
        .unwrap();
    assert_eq!(call(p.clone(), quote()).await.0, StatusCode::OK);
    // The metrics show the watch.
    let rows = app.store.merchant_watch_flags().await.unwrap();
    let text = chain_payments_service::metrics::Metrics::render_watch(&rows);
    assert!(text.contains("chain_payments_merchant_pending_recipient{merchant=\"0x30b6\"} 0"), "{text}");
}

#[tokio::test]
async fn a_payment_no_checkout_submitted_is_found_from_its_event() {
    let Some(app) = app().await else { return };
    let m = merchant_router(app.clone());
    let p = public_router(app.clone());
    let (_, _, v) =
        call(m, post("/v1/merchant/sessions", json!({"amountPence": 300, "description": "1 month"}), Some(KEY))).await;
    let id = v["id"].as_str().unwrap().to_string();
    let (_, _, q) =
        call(p.clone(), post(&format!("/v1/sessions/{id}/quotes"), json!({"method": "sui-testnet:GBPT"}), None)).await;
    let nonce = q["nonce"].as_str().unwrap().to_string();
    use base64::Engine;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    // A stand-in GraphQL endpoint: one event pays our quote (never submitted), one is someone else's.
    let digest = "33nefFTR2NG3LcCYzpnRjEsvu6gBTNhgMeDc9EyCqvFa";
    let answer = json!({"data":{"events":{"pageInfo":{"hasNextPage":false,"endCursor":"C1"},"nodes":[
        {"transaction":{"digest": digest},"contents":{"json":{"nonce": b64(&nonce)}}},
        {"transaction":{"digest":"4JFuen7pDZCzqdRwUmB4oCwbeJ7Xqw5DqBsupvwyX1wb"},"contents":{"json":{"nonce": b64("ffffffffffffffffffffffffffffffff")}}}
    ]}}});
    let router = axum::Router::new().route("/graphql", axum::routing::post(move || async move { axum::Json(answer) }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/graphql", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    let client = reqwest::Client::new();
    chain_payments_service::worker::reconcile_package(&app, &client, &url, "0x5f67").await.unwrap();
    let claim = app.store.payment(digest, &nonce).await.unwrap().expect("claimed from the event");
    assert_eq!(
        (claim.session_id.as_str(), claim.status.as_str()),
        (id.as_str(), "pending"),
        "verified later like any claim"
    );
    assert_eq!(app.store.event_cursor("0x5f67").await.unwrap().as_deref(), Some("C1"));
    // A second pass changes nothing.
    chain_payments_service::worker::reconcile_package(&app, &client, &url, "0x5f67").await.unwrap();
    assert!(!app.store.claim_found_payment(digest, &nonce).await.unwrap(), "once");
}
