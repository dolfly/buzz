//! Concurrency-matrix tests for the Databricks auth coordinator.
//!
//! The coordinator single-flights OAuth acquisition per cache key using an OS
//! advisory lock, so one browser dance is shared and failures are coalesced
//! through a durable cooldown sidecar. These tests drive the public API
//! (`acquire_with_intent`, `interactive_login`) with an injected
//! [`BrowserOpener`] that scripts the localhost callback instead of popping a
//! real window — the browser step becomes deterministic and countable.
//!
//! Two `PkceOAuthTokenSource` instances sharing one cache path model two
//! processes: `File::try_lock` is per open-file-description, so distinct
//! handles contend whether or not they live in the same process. The
//! lock-primitive, crash-release, and lock-timeout edges live in the in-crate
//! `auth::tests` module where the private helpers are reachable.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Form;
use axum::{routing::get, routing::post, Json, Router};
use buzz_agent::auth::{
    AuthError, AuthIntent, BrowserOpener, PkceOAuthConfig, PkceOAuthTokenSource,
};
use serde::Deserialize;
use serde_json::json;
use tempfile::TempDir;

// ---- scripted browser opener --------------------------------------------

/// What the scripted "user" does when the coordinator opens a browser.
#[derive(Clone, Copy)]
enum Script {
    /// Redirect with a valid `code`+`state` → the flow exchanges it for a
    /// token and succeeds.
    Approve,
    /// Redirect with `error=access_denied` → the flow returns `Denied`.
    Deny,
    /// Every launch strategy fails → the flow returns `BrowserOpenFailed`
    /// without waiting on a listener nobody will reach.
    FailToOpen,
}

/// A [`BrowserOpener`] that counts launches and drives the localhost callback
/// on a background thread, so the caller's callback wait observes the redirect
/// exactly as a real browser would deliver it.
#[derive(Clone)]
struct ScriptedOpener {
    script: Script,
    calls: Arc<AtomicU64>,
}

impl ScriptedOpener {
    fn new(script: Script) -> Self {
        Self {
            script,
            calls: Arc::new(AtomicU64::new(0)),
        }
    }

    fn call_count(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl BrowserOpener for ScriptedOpener {
    fn open(&self, url: &str) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let query = match self.script {
            Script::FailToOpen => return Err("no browser available".into()),
            Script::Approve => "code=scripted-code",
            Script::Deny => "error=access_denied",
        };
        // Pull the loopback redirect target and the anti-CSRF state out of the
        // authorize URL, then fire the callback from a separate thread so this
        // synchronous `open()` returns and the flow proceeds to await it.
        let parsed = url::Url::parse(url).expect("authorize URL must parse");
        let redirect = parsed
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .map(|(_, v)| v.into_owned())
            .expect("authorize URL carries redirect_uri");
        let state = parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .expect("authorize URL carries state");
        let redirect = url::Url::parse(&redirect).expect("redirect_uri must parse");
        // The coordinator's listener binds 127.0.0.1; connect there directly so
        // the callback can't land on an IPv6 `localhost` (::1) with no listener.
        let port = redirect.port().expect("loopback redirect carries a port");
        // `state` is base64url (no reserved characters), safe to inline.
        let request = format!(
            "GET /?{query}&state={state} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        std::thread::spawn(move || {
            // A real browser holds the connection open until the callback page
            // responds; do the same so hyper dispatches the request before the
            // socket closes (a bare write+drop races the server and is lost).
            if let Ok(mut sock) = TcpStream::connect(("127.0.0.1", port)) {
                use std::io::Read;
                let _ = sock.write_all(request.as_bytes());
                let _ = sock.flush();
                let mut discard = Vec::new();
                let _ = sock.read_to_end(&mut discard);
            }
        });
        Ok(())
    }
}

// ---- stub OIDC provider --------------------------------------------------

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
}

struct Stub {
    base: String,
    /// authorization-code exchanges served (browser flows completed).
    code_grants: Arc<AtomicU64>,
    /// refresh-token grants served.
    refresh_grants: Arc<AtomicU64>,
}

/// Boot a stub provider. `reject_refresh` makes the token endpoint 401 every
/// refresh-token grant (a dead refresh token); authorization-code grants
/// always succeed with a fresh token.
async fn spawn_stub(reject_refresh: bool) -> Stub {
    let code_grants = Arc::new(AtomicU64::new(0));
    let refresh_grants = Arc::new(AtomicU64::new(0));

    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let disco_base = base.clone();

    let discovery = move || {
        let base = disco_base.clone();
        async move {
            Json(json!({
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
            }))
        }
    };

    let code_for_token = code_grants.clone();
    let refresh_for_token = refresh_grants.clone();
    let app = Router::new()
        // Two discovery paths so distinct-host tests derive distinct cache
        // keys (the key hashes the discovery URL) from one stub.
        .route("/disco/a", get(discovery.clone()))
        .route("/disco/b", get(discovery))
        .route(
            "/token",
            post(move |Form(form): Form<TokenForm>| {
                let code_grants = code_for_token.clone();
                let refresh_grants = refresh_for_token.clone();
                let reject_refresh = reject_refresh;
                async move {
                    if form.grant_type == "refresh_token" {
                        let n = refresh_grants.fetch_add(1, Ordering::SeqCst) + 1;
                        if reject_refresh {
                            return (
                                axum::http::StatusCode::UNAUTHORIZED,
                                Json(json!({ "error": "invalid_grant" })),
                            );
                        }
                        return (
                            axum::http::StatusCode::OK,
                            Json(json!({
                                "access_token": format!("refreshed-token-{n}"),
                                "refresh_token": "rotated-refresh",
                                "expires_in": 3600,
                            })),
                        );
                    }
                    let n = code_grants.fetch_add(1, Ordering::SeqCst) + 1;
                    (
                        axum::http::StatusCode::OK,
                        Json(json!({
                            "access_token": format!("browser-token-{n}"),
                            "refresh_token": "browser-refresh",
                            "expires_in": 3600,
                        })),
                    )
                }
            }),
        );

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Stub {
        base,
        code_grants,
        refresh_grants,
    }
}

fn config(stub: &Stub, disco_path: &str, cache_dir: &std::path::Path) -> PkceOAuthConfig {
    PkceOAuthConfig {
        discovery_url: format!("{}{disco_path}", stub.base),
        client_id: "test-client".into(),
        scopes: vec!["offline_access".into()],
        cache_namespace: "databricks".into(),
        cache_dir_override: Some(cache_dir.to_path_buf()),
    }
}

fn future_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600
}

fn seed_cache(cfg: &PkceOAuthConfig, cache_dir: &std::path::Path, body: serde_json::Value) {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(cfg.discovery_url.as_bytes());
    h.update(b"|");
    h.update(cfg.client_id.as_bytes());
    h.update(b"|");
    h.update(cfg.scopes.join(",").as_bytes());
    let hash = hex::encode(h.finalize());
    let path = cache_dir
        .join(&cfg.cache_namespace)
        .join(format!("{hash}.json"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
}

// ---- acceptance matrix ---------------------------------------------------

#[tokio::test]
async fn test_same_key_concurrent_callers_share_one_browser_attempt() {
    let stub = spawn_stub(false).await;
    let cache = TempDir::new().unwrap();
    let opener = ScriptedOpener::new(Script::Approve);

    // Two independent sources on the SAME cache key = two processes racing.
    let a = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(opener.clone()),
    )
    .unwrap();
    let b = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(opener.clone()),
    )
    .unwrap();

    let (ra, rb) = tokio::join!(
        a.acquire_with_intent(AuthIntent::Auto),
        b.acquire_with_intent(AuthIntent::Auto),
    );
    let ta = ra.expect("first caller authenticates");
    let tb = rb.expect("second caller authenticates");

    // One browser launch, one code exchange, one shared token.
    assert_eq!(
        opener.call_count(),
        1,
        "only one browser attempt for one key"
    );
    assert_eq!(
        stub.code_grants.load(Ordering::SeqCst),
        1,
        "exactly one authorization-code exchange"
    );
    assert_eq!(ta, tb, "both callers observe the same token");
    assert_eq!(ta, "browser-token-1");
}

#[tokio::test]
async fn test_denied_then_auto_reads_cooldown_without_second_launch() {
    let stub = spawn_stub(false).await;
    let cache = TempDir::new().unwrap();
    let opener = ScriptedOpener::new(Script::Deny);

    let src = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(opener.clone()),
    )
    .unwrap();

    let first = src.acquire_with_intent(AuthIntent::Auto).await;
    assert_eq!(
        first,
        Err(AuthError::Denied),
        "first Auto attempt is denied"
    );
    assert_eq!(opener.call_count(), 1);

    // The denial wrote a cooldown; a subsequent Auto caller reads it and
    // returns the recorded outcome instead of popping a second browser.
    let second = src.acquire_with_intent(AuthIntent::Auto).await;
    assert_eq!(
        second,
        Err(AuthError::Denied),
        "queued Auto caller honors the cooldown"
    );
    assert_eq!(
        opener.call_count(),
        1,
        "cooldown suppresses the second browser launch"
    );
}

#[tokio::test]
async fn test_userinitiated_denial_is_visible_to_crossprocess_auto() {
    let stub = spawn_stub(false).await;
    let cache = TempDir::new().unwrap();
    let opener = ScriptedOpener::new(Script::Deny);

    // Process A: an explicit UserInitiated attempt is denied.
    let proc_a = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(opener.clone()),
    )
    .unwrap();
    let denied = proc_a.acquire_with_intent(AuthIntent::UserInitiated).await;
    assert_eq!(denied, Err(AuthError::Denied));
    assert_eq!(opener.call_count(), 1);

    // Process B: a passive Auto caller (distinct instance = distinct process)
    // reads the durable sidecar A wrote and does not launch a second browser.
    // This is the cross-policy edge: the sidecar is written for ANY failed
    // interactive attempt, only the reader policy differs.
    let proc_b = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(opener.clone()),
    )
    .unwrap();
    let auto = proc_b.acquire_with_intent(AuthIntent::Auto).await;
    assert_eq!(
        auto,
        Err(AuthError::Denied),
        "cross-process Auto reads the UserInitiated failure sidecar"
    );
    assert_eq!(
        opener.call_count(),
        1,
        "no second browser across the policy/process boundary"
    );
}

#[tokio::test]
async fn test_userinitiated_retry_bypasses_cooldown_and_reopens() {
    let stub = spawn_stub(false).await;
    let cache = TempDir::new().unwrap();

    // First attempt: denied, writes a cooldown.
    let deny_opener = ScriptedOpener::new(Script::Deny);
    let denier = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(deny_opener.clone()),
    )
    .unwrap();
    assert_eq!(
        denier.acquire_with_intent(AuthIntent::UserInitiated).await,
        Err(AuthError::Denied)
    );

    // The user explicitly retries: UserInitiated bypasses (and clears) the
    // cooldown and opens a fresh browser, which now succeeds.
    let approve_opener = ScriptedOpener::new(Script::Approve);
    let retrier = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(approve_opener.clone()),
    )
    .unwrap();
    let token = retrier
        .acquire_with_intent(AuthIntent::UserInitiated)
        .await
        .expect("explicit retry re-launches the browser and succeeds");
    assert_eq!(token, "browser-token-1");
    assert_eq!(
        approve_opener.call_count(),
        1,
        "UserInitiated retry launches despite the prior cooldown"
    );

    // Cooldown cleared on success: a follow-up Auto now sees a valid token,
    // never the stale denial.
    let auto = retrier.acquire_with_intent(AuthIntent::Auto).await;
    assert_eq!(auto, Ok("browser-token-1".to_string()));
}

#[tokio::test]
async fn test_distinct_hosts_do_not_inherit_cooldown() {
    let stub = spawn_stub(false).await;
    let cache = TempDir::new().unwrap();

    // Host A is denied and records a cooldown under key A.
    let deny_opener = ScriptedOpener::new(Script::Deny);
    let host_a = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(deny_opener.clone()),
    )
    .unwrap();
    assert_eq!(
        host_a.acquire_with_intent(AuthIntent::Auto).await,
        Err(AuthError::Denied)
    );

    // Host B is a different key (different discovery URL). It must NOT inherit
    // A's cooldown: an Auto caller launches its own browser and succeeds.
    let approve_opener = ScriptedOpener::new(Script::Approve);
    let host_b = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/b", cache.path()),
        Arc::new(approve_opener.clone()),
    )
    .unwrap();
    let token = host_b
        .acquire_with_intent(AuthIntent::Auto)
        .await
        .expect("distinct host is unaffected by another key's cooldown");
    assert_eq!(token, "browser-token-1");
    assert_eq!(approve_opener.call_count(), 1);
}

#[tokio::test]
async fn test_browser_open_failure_is_typed_and_retryable_by_user() {
    let stub = spawn_stub(false).await;
    let cache = TempDir::new().unwrap();

    // Every launch strategy fails: the flow reports the typed BrowserOpenFailed
    // without waiting on a listener nobody will reach.
    let fail_opener = ScriptedOpener::new(Script::FailToOpen);
    let failing = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(fail_opener.clone()),
    )
    .unwrap();
    let result = failing.acquire_with_intent(AuthIntent::UserInitiated).await;
    assert_eq!(
        result,
        Err(AuthError::BrowserOpenFailed),
        "a failed launch surfaces as the typed BrowserOpenFailed"
    );
    assert_eq!(fail_opener.call_count(), 1);

    // A failed launch writes a cooldown, but a UserInitiated retry bypasses it
    // and reopens — a transient "no browser" (e.g. race with a display coming
    // up) must never wedge an explicit user sign-in.
    let approve_opener = ScriptedOpener::new(Script::Approve);
    let retrier = PkceOAuthTokenSource::new_with(
        config(&stub, "/disco/a", cache.path()),
        Arc::new(approve_opener.clone()),
    )
    .unwrap();
    let token = retrier
        .acquire_with_intent(AuthIntent::UserInitiated)
        .await
        .expect("explicit retry reopens despite the prior launch failure");
    assert_eq!(token, "browser-token-1");
    assert_eq!(approve_opener.call_count(), 1);
}

#[tokio::test]
async fn test_headless_dead_refresh_returns_refresh_rejected_without_browser() {
    let stub = spawn_stub(true).await; // refresh grants 401
    let cache = TempDir::new().unwrap();
    let opener = ScriptedOpener::new(Script::Approve);
    let cfg = config(&stub, "/disco/a", cache.path());

    // Expired token WITH a refresh token, but the server rejects the refresh
    // grant (dead/rotated). A Headless caller must classify this terminally as
    // RefreshRejected and never open a browser.
    seed_cache(
        &cfg,
        cache.path(),
        json!({
            "access_token": "stale",
            "refresh_token": "dead-refresh",
            "expires_at": 1u64,
        }),
    );

    let src = PkceOAuthTokenSource::new_with(cfg, Arc::new(opener.clone())).unwrap();
    let result = src.acquire_with_intent(AuthIntent::Headless).await;
    assert_eq!(
        result,
        Err(AuthError::RefreshRejected),
        "Headless dead-refresh is terminal RefreshRejected"
    );
    assert_eq!(opener.call_count(), 0, "Headless never opens a browser");
    assert_eq!(
        stub.refresh_grants.load(Ordering::SeqCst),
        1,
        "the refresh grant was attempted exactly once"
    );
}

#[tokio::test]
async fn test_interactive_dead_refresh_converts_to_browser() {
    let stub = spawn_stub(true).await; // refresh grants 401
    let cache = TempDir::new().unwrap();
    let opener = ScriptedOpener::new(Script::Approve);
    let cfg = config(&stub, "/disco/a", cache.path());

    // Same dead-refresh seed, but an interactive intent must fall through to a
    // browser flow instead of failing terminally.
    seed_cache(
        &cfg,
        cache.path(),
        json!({
            "access_token": "stale",
            "refresh_token": "dead-refresh",
            "expires_at": 1u64,
        }),
    );

    let src = PkceOAuthTokenSource::new_with(cfg, Arc::new(opener.clone())).unwrap();
    let token = src
        .acquire_with_intent(AuthIntent::UserInitiated)
        .await
        .expect("interactive intent recovers via the browser");
    assert_eq!(token, "browser-token-1");
    assert_eq!(opener.call_count(), 1, "interactive intent opens a browser");
    assert_eq!(stub.refresh_grants.load(Ordering::SeqCst), 1);
    assert_eq!(stub.code_grants.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_headless_expired_token_live_refresh_recovers_silently() {
    let stub = spawn_stub(false).await; // refresh succeeds
    let cache = TempDir::new().unwrap();
    let opener = ScriptedOpener::new(Script::Approve);
    let cfg = config(&stub, "/disco/a", cache.path());

    seed_cache(
        &cfg,
        cache.path(),
        json!({
            "access_token": "stale",
            "refresh_token": "live-refresh",
            "expires_at": 1u64,
        }),
    );

    let src = PkceOAuthTokenSource::new_with(cfg, Arc::new(opener.clone())).unwrap();
    let token = src
        .acquire_with_intent(AuthIntent::Headless)
        .await
        .expect("live refresh recovers a Headless caller silently");
    assert_eq!(token, "refreshed-token-1");
    assert_eq!(opener.call_count(), 0, "no browser on a live refresh");
    assert_eq!(stub.refresh_grants.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_interactive_login_reuses_valid_cache_without_browser() {
    let stub = spawn_stub(false).await;
    let cache = TempDir::new().unwrap();
    let opener = ScriptedOpener::new(Script::Approve);
    let cfg = config(&stub, "/disco/a", cache.path());

    // A still-valid cached token short-circuits interactive_login: an explicit
    // sign-in should not re-prompt when a good token is already present.
    seed_cache(
        &cfg,
        cache.path(),
        json!({
            "access_token": "already-valid",
            "refresh_token": "rt",
            "expires_at": future_secs(),
        }),
    );

    let src = PkceOAuthTokenSource::new_with(cfg, Arc::new(opener.clone())).unwrap();
    src.interactive_login()
        .await
        .expect("interactive_login succeeds off the valid cache");
    assert_eq!(
        opener.call_count(),
        0,
        "a valid cached token means no browser prompt"
    );
}
