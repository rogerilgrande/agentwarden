//! HTTP server: routes, handlers, the policy-reload daemon, and graceful shutdown.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::{FromRequest, Request, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

use crate::config::Config;
use crate::engine;
use crate::error::GateError;
use crate::policy::{FilePolicyStore, PolicyStore};
use crate::types::{AdminKey, Decision, ToolCall};

/// Shared, cheaply-cloneable application state injected into every handler.
#[derive(Clone)]
pub(crate) struct AppState {
    store: Arc<dyn PolicyStore>,
    /// When set, gates `POST /reload` behind a matching `x-admin-key` header.
    admin_key: Option<AdminKey>,
}

/// A JSON body extractor that funnels deserialization and validation failures
/// through `GateError`, so every error response shares one shape and the
/// 4xx-informative / 5xx-redacted policy in `error.rs` actually applies.
pub(crate) struct ValidatedJson<T>(pub(crate) T);

impl<S, T> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = GateError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|rej| GateError::InvalidRequest(rej.body_text()))?;
        Ok(ValidatedJson(value))
    }
}

/// Build the router for a given state. Factored out so tests can drive it directly.
pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/evaluate", post(evaluate_handler))
        .route("/reload", post(reload_handler))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

pub(crate) async fn serve(config: Config) -> anyhow::Result<()> {
    init_tracing();
    tracing::info!(?config, "starting agentwarden");

    let store = FilePolicyStore::load(config.policy_path.clone())
        .await
        .with_context(|| {
            format!(
                "loading initial policy from {}",
                config.policy_path.display()
            )
        })?;

    let state = AppState {
        store: store.clone(),
        admin_key: config.admin_key.clone(),
    };

    let cancel = CancellationToken::new();
    let tracker = TaskTracker::new();
    if config.reload_secs > 0 {
        tracker.spawn(
            reload_daemon(store.clone(), cancel.clone(), config.reload_secs)
                .instrument(tracing::info_span!("reload_daemon")),
        );
    } else {
        tracing::info!("hot-reload disabled (AGENTWARDEN_RELOAD_SECS=0)");
    }
    tracker.close();

    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("binding {}", config.addr))?;
    tracing::info!(addr = %config.addr, "agentwarden listening");

    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    cancel.cancel();
    tracker.wait().await;
    tracing::info!("shutdown complete");
    Ok(())
}

/// Periodically reload the policy until cancelled. The first reload is scheduled
/// one interval out (the policy was just loaded at startup), and a bad file is
/// logged while the previous good policy stays active.
async fn reload_daemon(store: Arc<FilePolicyStore>, cancel: CancellationToken, secs: u64) {
    let period = Duration::from_secs(secs);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    loop {
        tokio::select! {
            _ = ticker.tick() => match store.reload().await {
                Ok(n) => tracing::info!(rules = n, "policy reloaded"),
                Err(e) => tracing::error!(error = %e, "reload failed; keeping previous policy"),
            },
            _ = cancel.cancelled() => {
                tracing::info!("reload daemon stopping");
                break;
            }
        }
    }
}

/// `POST /evaluate`: validate the tool call, evaluate it, return the verdict.
async fn evaluate_handler(
    State(state): State<AppState>,
    ValidatedJson(call): ValidatedJson<ToolCall>,
) -> Result<Json<Decision>, GateError> {
    tracing::debug!(session = ?call.session, "evaluate request");
    let policy = state.store.current().await;
    Ok(Json(engine::evaluate(&policy, &call)))
}

/// `POST /reload`: force an immediate policy reload. Disabled (403) unless an
/// admin key is configured; otherwise requires a matching `x-admin-key` header.
async fn reload_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, GateError> {
    let Some(expected) = &state.admin_key else {
        return Err(GateError::Forbidden);
    };
    let provided = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    // Constant-time compare so a wrong key can't be recovered by timing.
    if !constant_time_eq::constant_time_eq(provided.as_bytes(), expected.expose().as_bytes()) {
        return Err(GateError::Unauthorized);
    }
    let n = state
        .store
        .reload()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "manual reload failed"))?;
    Ok(Json(json!({ "reloaded": n })))
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Logs go to stderr; stdout is reserved for program output (e.g. the `check` subcommand's JSON).
    fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();
}

/// Resolve when the process receives Ctrl-C or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{MockPolicyStore, sample_policy};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use tower::ServiceExt; // for `oneshot`

    fn state_with_key(admin: Option<&str>) -> AppState {
        let mut store = MockPolicyStore::new();
        store
            .expect_current()
            .returning(|| Arc::new(sample_policy()));
        AppState {
            store: Arc::new(store),
            admin_key: admin.map(|s| AdminKey::new(s.to_owned())),
        }
    }

    fn post(uri: &str, body: &'static str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("request builds")
    }

    async fn body_text(resp: axum::response::Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body is readable");
        String::from_utf8(bytes.to_vec()).expect("response body is valid utf-8")
    }

    #[tokio::test]
    async fn evaluate_returns_a_decision() {
        let resp = router(state_with_key(None))
            .oneshot(post(
                "/evaluate",
                r#"{"tool":"bash","command":"rm -rf /","agent":"claude-code"}"#,
            ))
            .await
            .expect("router handles request");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_text(resp).await.contains("\"deny\""));
    }

    #[tokio::test]
    async fn bad_agent_is_422_with_error_envelope() {
        // Validation now flows through GateError -> the {"error":...} envelope.
        let resp = router(state_with_key(None))
            .oneshot(post(
                "/evaluate",
                r#"{"tool":"bash","command":"ls","agent":"Bad Name!"}"#,
            ))
            .await
            .expect("router handles request");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body_text(resp).await.contains("\"error\""));
    }

    #[tokio::test]
    async fn reload_is_forbidden_without_a_configured_key() {
        let resp = router(state_with_key(None))
            .oneshot(post("/reload", ""))
            .await
            .expect("router handles request");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn reload_rejects_a_wrong_key() {
        let req = Request::builder()
            .method("POST")
            .uri("/reload")
            .header("x-admin-key", "wrong")
            .body(Body::empty())
            .expect("request builds");
        let resp = router(state_with_key(Some("secret")))
            .oneshot(req)
            .await
            .expect("router handles request");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn into_response_redacts_server_errors_but_not_client_errors() {
        let server = GateError::EmptyRule { id: 3 }.into_response();
        assert_eq!(server.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_text(server).await;
        assert!(body.contains("internal error"));
        assert!(!body.contains("rule 3")); // internal detail is redacted

        let client = GateError::InvalidRequest("boom".into()).into_response();
        assert_eq!(client.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body_text(client).await.contains("boom"));
    }
}
