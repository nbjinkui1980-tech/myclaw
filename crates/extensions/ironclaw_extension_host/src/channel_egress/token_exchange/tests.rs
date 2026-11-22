//! Token exchange through the real host-runtime egress path: a scripted network
//! stands in for the vendor (a token endpoint and a send endpoint), time is
//! paused, and every assertion is made on the requests the network saw.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use ironclaw_authorization::GrantAuthorizer;
use ironclaw_extension_contracts::tool_adapter::RestrictedEgressError;
use ironclaw_extension_host::egress::{
    ApprovedChannelCredential, ApprovedChannelEgress, ApprovedCredentialSource,
    ChannelEgressTransport,
};
use ironclaw_extension_registry::ExtensionRegistry;
use ironclaw_filesystem::DiskFilesystem;
use ironclaw_host_api::{
    action::NetworkMethod,
    http::RuntimeCredentialTarget,
    ids::{InvocationId, SecretHandle, UserId},
    resource::ResourceScope,
};
use ironclaw_host_runtime::{
    CapabilitySurfaceVersion, HostRuntimeHttpEgressPort, HostRuntimeServices,
};
use ironclaw_network::{
    NetworkHttpEgress, NetworkHttpError, NetworkHttpRequest, NetworkHttpResponse, NetworkUsage,
};
use ironclaw_processes::in_memory_backed_process_services;
use ironclaw_resources::InMemoryResourceGovernor;
use ironclaw_secrets::SecretStore;
use secrecy::SecretString;

use super::*;
use crate::channel_egress::{
    HostRuntimeChannelEgressTransport, SecretStoreChannelEgressCredentials,
};

const TOKEN_URL: &str = "https://auth.acme.example/v1/oauth/token";
const SEND_URL: &str = "https://api.acme.example/v1/messages";
const APP_KEY: &str = "APP-KEY-SENTINEL-1111";
const APP_SECRET: &str = "APP-SECRET-SENTINEL-2222";

#[derive(Debug, Clone)]
struct Recorded {
    url: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone)]
enum Step {
    Respond {
        status: u16,
        body: String,
        delay: Duration,
    },
    Fail,
}

fn respond(status: u16, body: &str) -> Step {
    Step::Respond {
        status,
        body: body.to_string(),
        delay: Duration::ZERO,
    }
}

fn token_ok(n: usize, expire_in: &str) -> Step {
    respond(
        200,
        &format!(r#"{{"accessToken":"TOKEN-{n}","expireIn":{expire_in}}}"#),
    )
}

type Responder = dyn Fn(&Recorded, usize) -> Step + Send + Sync;

/// A vendor: `responder(request, nth_request_to_that_url)`.
struct ScriptedNetwork {
    requests: Arc<Mutex<Vec<Recorded>>>,
    counts: Mutex<HashMap<String, usize>>,
    responder: Arc<Responder>,
}

#[async_trait]
impl NetworkHttpEgress for ScriptedNetwork {
    async fn execute(
        &self,
        request: NetworkHttpRequest,
    ) -> Result<NetworkHttpResponse, NetworkHttpError> {
        let recorded = Recorded {
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: String::from_utf8_lossy(&request.body).to_string(),
        };
        let nth = {
            let mut counts = self.counts.lock().unwrap();
            let count = counts.entry(recorded.url.clone()).or_default();
            *count += 1;
            *count
        };
        let step = (self.responder)(&recorded, nth);
        self.requests.lock().unwrap().push(recorded);
        match step {
            Step::Respond {
                status,
                body,
                delay,
            } => {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                Ok(NetworkHttpResponse {
                    status,
                    headers: Vec::new(),
                    usage: NetworkUsage {
                        request_bytes: 0,
                        response_bytes: body.len() as u64,
                        resolved_ip: None,
                    },
                    body: body.into_bytes(),
                })
            }
            Step::Fail => Err(NetworkHttpError::Transport {
                reason: "connection reset: TOKEN-LEAK-CANARY".to_string(),
                request_bytes: 0,
                response_bytes: 0,
            }),
        }
    }
}

struct Harness {
    transport: HostRuntimeChannelEgressTransport,
    exchange: Arc<TokenExchangeEgressCredentials>,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl Harness {
    fn at(&self, url: &str) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.url == url)
            .cloned()
            .collect()
    }
}

fn services() -> HostRuntimeServices<DiskFilesystem, InMemoryResourceGovernor> {
    HostRuntimeServices::new(
        Arc::new(ExtensionRegistry::new()),
        Arc::new(DiskFilesystem::new()),
        Arc::new(InMemoryResourceGovernor::new()),
        Arc::new(GrantAuthorizer::new()),
        in_memory_backed_process_services(),
        CapabilitySurfaceVersion::new("surface-v1").unwrap(),
    )
}

fn port_over(network: ScriptedNetwork) -> HostRuntimeHttpEgressPort {
    services()
        .with_secret_store(Arc::new(SecretStore::ephemeral()))
        .try_with_host_http_egress(network)
        .unwrap()
        .host_runtime_http_egress_port()
        .unwrap()
}

fn scope() -> ResourceScope {
    ResourceScope::local_default(UserId::new("token-user").unwrap(), InvocationId::new()).unwrap()
}

async fn app_credentials(scope: &ResourceScope) -> Arc<dyn ChannelEgressCredentialsPort> {
    use ironclaw_secrets::SecretStorePort as _;
    let store = Arc::new(SecretStore::ephemeral());
    for (handle, value) in [("acme_app_key", APP_KEY), ("acme_app_secret", APP_SECRET)] {
        store
            .put(
                scope.clone(),
                SecretHandle::new(handle).unwrap(),
                SecretString::from(value.to_string()),
                None,
            )
            .await
            .unwrap();
    }
    Arc::new(SecretStoreChannelEgressCredentials::new(
        store as Arc<dyn ironclaw_secrets::SecretStorePort>,
        scope.clone(),
    ))
}

async fn harness(responder: impl Fn(&Recorded, usize) -> Step + Send + Sync + 'static) -> Harness {
    let scope = scope();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let port = port_over(ScriptedNetwork {
        requests: Arc::clone(&requests),
        counts: Mutex::new(HashMap::new()),
        responder: Arc::new(responder),
    });
    let exchange = Arc::new(TokenExchangeEgressCredentials::new(
        app_credentials(&scope).await,
        port.clone(),
        scope.clone(),
    ));
    Harness {
        transport: HostRuntimeChannelEgressTransport::new(port, exchange.clone(), scope),
        exchange,
        requests,
    }
}

fn app_pointer(handle: &str, pointer: &str) -> ApprovedChannelCredential {
    ApprovedChannelCredential {
        handle: SecretHandle::new(handle).unwrap(),
        target: RuntimeCredentialTarget::BodyJsonPointer {
            pointer: pointer.to_string(),
            post_injection_body_limit_bytes: None,
        },
    }
}

fn source() -> ApprovedCredentialSource {
    ApprovedCredentialSource {
        handle: SecretHandle::new("acme_access_token").unwrap(),
        url: TOKEN_URL.to_string(),
        host: "auth.acme.example".to_string(),
        method: NetworkMethod::Post,
        body: br#"{"grantType":"client_credentials"}"#.to_vec(),
        credentials: vec![
            app_pointer("acme_app_key", "/appKey"),
            app_pointer("acme_app_secret", "/appSecret"),
        ],
        request_body_limit: None,
        response_body_limit: 4096,
        token_pointer: "/accessToken".to_string(),
        expires_in_pointer: "/expireIn".to_string(),
    }
}

fn plan() -> ApprovedChannelEgress {
    ApprovedChannelEgress {
        extension_id: "acme-messenger-token".to_string(),
        installation_id: "inst-1".to_string(),
        method: NetworkMethod::Post,
        url: SEND_URL.to_string(),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: br#"{"text":"hello"}"#.to_vec(),
        host: "api.acme.example".to_string(),
        credential: Some(ApprovedChannelCredential {
            handle: SecretHandle::new("acme_access_token").unwrap(),
            target: RuntimeCredentialTarget::Header {
                name: "x-acme-access-token".to_string(),
                prefix: Some("Token ".to_string()),
            },
        }),
        body_credentials: Vec::new(),
        request_body_limit: None,
        response_body_limit: 64 * 1024,
        timeout_ms: 5_000,
        credential_source: Some(source()),
    }
}

/// A vendor whose token endpoint hands out `TOKEN-1`, `TOKEN-2`, ... and whose
/// send endpoint accepts only the newest token it has issued.
fn healthy_vendor(expire_in: &'static str) -> impl Fn(&Recorded, usize) -> Step + Send + Sync {
    let issued = Arc::new(AtomicUsize::new(0));
    move |request, _nth| {
        if request.url == TOKEN_URL {
            let n = issued.fetch_add(1, Ordering::SeqCst) + 1;
            token_ok(n, expire_in)
        } else {
            let current = format!("Token TOKEN-{}", issued.load(Ordering::SeqCst));
            if request.header("x-acme-access-token") == Some(current.as_str()) {
                respond(200, r#"{"ok":true}"#)
            } else {
                respond(401, r#"{"error":"bad token"}"#)
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn first_send_exchanges_once_and_injects_the_declared_header() {
    let harness = harness(healthy_vendor("7200")).await;
    let response = harness.transport.execute(plan()).await.unwrap();
    assert_eq!(response.status, 200);
    let exchanges = harness.at(TOKEN_URL);
    assert_eq!(exchanges.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&exchanges[0].body).unwrap();
    assert_eq!(body["appKey"], APP_KEY);
    assert_eq!(body["appSecret"], APP_SECRET);
    assert_eq!(body["grantType"], "client_credentials");
    let sends = harness.at(SEND_URL);
    assert_eq!(sends.len(), 1);
    assert_eq!(
        sends[0].header("x-acme-access-token"),
        Some("Token TOKEN-1")
    );
    assert!(!sends[0].body.contains("TOKEN-1") && !sends[0].body.contains(APP_SECRET));
}

#[tokio::test(start_paused = true)]
async fn a_cached_token_is_reused_until_the_refresh_time() {
    let harness = harness(healthy_vendor("7200")).await;
    harness.transport.execute(plan()).await.unwrap();
    harness.transport.execute(plan()).await.unwrap();
    assert_eq!(
        harness.at(TOKEN_URL).len(),
        1,
        "second send reuses the token"
    );

    // 7200s lifetime, margin 300s: refresh at 6900s.
    tokio::time::advance(Duration::from_secs(6899)).await;
    harness.transport.execute(plan()).await.unwrap();
    assert_eq!(harness.at(TOKEN_URL).len(), 1, "still before refresh_at");

    tokio::time::advance(Duration::from_secs(2)).await;
    let response = harness.transport.execute(plan()).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(harness.at(TOKEN_URL).len(), 2, "refreshed ahead of expiry");
    let sends = harness.at(SEND_URL);
    assert_eq!(
        sends.last().unwrap().header("x-acme-access-token"),
        Some("Token TOKEN-2")
    );
}

#[test]
fn refresh_timing_is_bounded_and_never_trusts_a_missing_expiry() {
    let secs = |s| Duration::from_secs(s);
    assert_eq!(
        refresh_after(Some(7200)),
        secs(6900),
        "margin capped at 300s"
    );
    assert_eq!(refresh_after(Some(1000)), secs(800), "margin is a fifth");
    assert_eq!(refresh_after(None), secs(240), "default 300s, margin 60s");
    assert_eq!(refresh_after(Some(0)), secs(240), "zero is not a lifetime");
    assert_eq!(refresh_after(Some(5)), secs(48), "floor 60s, margin 12s");
    assert_eq!(
        refresh_after(Some(10 * 24 * 3600)),
        secs(24 * 3600 - 300),
        "capped at 24h"
    );
}

#[tokio::test(start_paused = true)]
async fn missing_tiny_and_string_expiries_use_the_bounded_values() {
    // (expireIn JSON, seconds after which a refresh must have happened,
    // seconds before which it must not have)
    for (expire_in, not_before, by) in [
        ("null", 239, 241),
        ("1", 47, 49),
        ("\"600\"", 479, 481),
        ("-5", 239, 241),
        ("\"soon\"", 239, 241),
    ] {
        let issued = Arc::new(AtomicUsize::new(0));
        let case = expire_in.to_string();
        let harness = harness(move |request, _| {
            if request.url == TOKEN_URL {
                let n = issued.fetch_add(1, Ordering::SeqCst) + 1;
                token_ok(n, &case)
            } else {
                respond(200, "{}")
            }
        })
        .await;
        harness.transport.execute(plan()).await.unwrap();
        tokio::time::advance(Duration::from_secs(not_before)).await;
        harness.transport.execute(plan()).await.unwrap();
        assert_eq!(harness.at(TOKEN_URL).len(), 1, "{expire_in}: too early");
        tokio::time::advance(Duration::from_secs(by - not_before)).await;
        harness.transport.execute(plan()).await.unwrap();
        assert_eq!(harness.at(TOKEN_URL).len(), 2, "{expire_in}: refreshed");
    }
}

#[tokio::test(start_paused = true)]
async fn concurrent_sends_share_one_exchange() {
    let issued = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&issued);
    let harness = harness(move |request, _| {
        if request.url == TOKEN_URL {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            Step::Respond {
                status: 200,
                body: format!(r#"{{"accessToken":"TOKEN-{n}","expireIn":7200}}"#),
                delay: Duration::from_millis(250),
            }
        } else {
            respond(200, "{}")
        }
    })
    .await;
    let results =
        futures::future::join_all((0..8).map(|_| harness.transport.execute(plan()))).await;
    assert!(results.iter().all(|result| result.is_ok()));
    assert_eq!(harness.at(TOKEN_URL).len(), 1, "single flight");
    let sends = harness.at(SEND_URL);
    assert_eq!(sends.len(), 8);
    assert!(
        sends
            .iter()
            .all(|send| send.header("x-acme-access-token") == Some("Token TOKEN-1"))
    );
}

#[tokio::test(start_paused = true)]
async fn a_rejected_token_is_refreshed_and_the_send_retried_exactly_once() {
    let issued = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&issued);
    let harness = harness(move |request, _| {
        if request.url == TOKEN_URL {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            token_ok(n, "7200")
        } else if request.header("x-acme-access-token") == Some("Token TOKEN-1") {
            respond(401, "{}")
        } else {
            respond(200, r#"{"ok":true}"#)
        }
    })
    .await;
    let response = harness.transport.execute(plan()).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(harness.at(TOKEN_URL).len(), 2);
    let sends = harness.at(SEND_URL);
    assert_eq!(sends.len(), 2, "one resend, no more");
    assert_eq!(
        sends[1].header("x-acme-access-token"),
        Some("Token TOKEN-2")
    );
}

#[tokio::test(start_paused = true)]
async fn a_second_401_is_returned_and_never_retried_again() {
    let issued = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&issued);
    let harness = harness(move |request, _| {
        if request.url == TOKEN_URL {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            token_ok(n, "7200")
        } else {
            respond(401, "{}")
        }
    })
    .await;
    let response = harness.transport.execute(plan()).await.unwrap();
    assert_eq!(response.status, 401, "the second answer is returned as-is");
    assert_eq!(harness.at(SEND_URL).len(), 2);
    assert_eq!(harness.at(TOKEN_URL).len(), 2);
}

#[tokio::test(start_paused = true)]
async fn concurrent_rejections_cause_one_replacement_exchange() {
    let issued = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&issued);
    let harness = harness(move |request, _| {
        if request.url == TOKEN_URL {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            token_ok(n, "7200")
        } else if request.header("x-acme-access-token") == Some("Token TOKEN-1") {
            respond(401, "{}")
        } else {
            respond(200, "{}")
        }
    })
    .await;
    // Prime TOKEN-1, then have several sends all fail with it at once.
    harness
        .exchange
        .exchanged_token(
            "acme-messenger-token",
            "inst-1",
            &source(),
            TokenRefresh::IfStale,
        )
        .await
        .unwrap();
    let results =
        futures::future::join_all((0..6).map(|_| harness.transport.execute(plan()))).await;
    assert!(
        results
            .iter()
            .all(|r| r.as_ref().is_ok_and(|r| r.status == 200))
    );
    assert_eq!(
        harness.at(TOKEN_URL).len(),
        2,
        "TOKEN-1 once, one replacement"
    );
}

#[tokio::test(start_paused = true)]
async fn server_errors_and_transport_failures_are_never_retried() {
    for status in [500u16, 503] {
        let harness = harness(move |request, _| {
            if request.url == TOKEN_URL {
                token_ok(1, "7200")
            } else {
                respond(status, "{}")
            }
        })
        .await;
        let response = harness.transport.execute(plan()).await.unwrap();
        assert_eq!(response.status, status);
        assert_eq!(harness.at(SEND_URL).len(), 1, "{status} must not be resent");
        assert_eq!(
            harness.at(TOKEN_URL).len(),
            1,
            "{status} must not re-exchange"
        );
    }
    let harness = harness(move |request, _| {
        if request.url == TOKEN_URL {
            token_ok(1, "7200")
        } else {
            Step::Fail
        }
    })
    .await;
    let error = harness.transport.execute(plan()).await.unwrap_err();
    assert!(matches!(error, RestrictedEgressError::Transport { .. }));
    assert_eq!(harness.at(SEND_URL).len(), 1, "a timeout is not resent");
    assert_eq!(harness.at(TOKEN_URL).len(), 1);
}

#[tokio::test(start_paused = true)]
async fn exchange_failures_map_onto_the_existing_error_classes() {
    let cases: Vec<(Step, &str)> = vec![
        (respond(401, "{}"), "auth"),
        (respond(403, "{}"), "auth"),
        (respond(503, "{}"), "transient"),
        (respond(429, "{}"), "transient"),
        (respond(200, "not json"), "transient"),
        (respond(200, r#"{"expireIn":7200}"#), "transient"),
        (
            respond(200, r#"{"accessToken":"","expireIn":7200}"#),
            "transient",
        ),
        (
            respond(200, r#"{"accessToken":"a\r\nb","expireIn":7200}"#),
            "transient",
        ),
        (Step::Fail, "transient"),
        (respond(302, "{}"), "permanent"),
        (respond(404, "{}"), "permanent"),
        (respond(400, "{}"), "permanent"),
    ];
    for (step, class) in cases {
        let scripted = step.clone();
        let harness = harness(move |request, _| {
            if request.url == TOKEN_URL {
                scripted.clone()
            } else {
                respond(200, "{}")
            }
        })
        .await;
        let error = harness.transport.execute(plan()).await.unwrap_err();
        match (class, &error) {
            (
                "auth",
                RestrictedEgressError::AuthRequired {
                    required_secrets, ..
                },
            ) => {
                let handles: Vec<&str> = required_secrets.iter().map(|h| h.as_str()).collect();
                assert_eq!(handles, ["acme_app_key", "acme_app_secret"]);
            }
            ("transient", RestrictedEgressError::Transport { reason }) => {
                assert_eq!(reason, "token exchange unavailable");
            }
            ("permanent", RestrictedEgressError::PolicyDenied) => {}
            other => panic!("unexpected mapping {other:?}"),
        }
        assert!(
            harness.at(SEND_URL).is_empty(),
            "a failed exchange must not send the payload"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_failed_exchange_is_not_cached_and_the_next_send_tries_again() {
    let harness = harness(move |request, nth| {
        if request.url == TOKEN_URL {
            if nth == 1 {
                respond(503, "{}")
            } else {
                token_ok(nth, "7200")
            }
        } else {
            respond(200, "{}")
        }
    })
    .await;
    assert!(harness.transport.execute(plan()).await.is_err());
    harness.transport.execute(plan()).await.unwrap();
    assert_eq!(harness.at(TOKEN_URL).len(), 2);
}

#[tokio::test(start_paused = true)]
async fn an_oversized_token_response_is_refused_without_sending() {
    let big = format!(
        r#"{{"accessToken":"TOKEN-1","expireIn":7200,"pad":"{}"}}"#,
        "x".repeat(20 * 1024)
    );
    let harness = harness(move |request, _| {
        if request.url == TOKEN_URL {
            respond(200, &big)
        } else {
            respond(200, "{}")
        }
    })
    .await;
    let error = harness.transport.execute(plan()).await.unwrap_err();
    assert!(matches!(error, RestrictedEgressError::PolicyDenied));
    assert!(harness.at(SEND_URL).is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_port_without_the_decorator_fails_closed_with_no_network_activity() {
    let scope = scope();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let port = port_over(ScriptedNetwork {
        requests: Arc::clone(&requests),
        counts: Mutex::new(HashMap::new()),
        responder: Arc::new(|_, _| respond(200, "{}")),
    });
    let plain = app_credentials(&scope).await;
    let transport = HostRuntimeChannelEgressTransport::new(port, plain, scope);
    let error = transport.execute(plan()).await.unwrap_err();
    assert!(matches!(error, RestrictedEgressError::PolicyDenied));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn requests_without_a_source_behave_as_before() {
    let harness = harness(healthy_vendor("7200")).await;
    let mut plain = plan();
    plain.credential = None;
    plain.credential_source = None;
    harness.transport.execute(plain).await.unwrap();
    assert!(harness.at(TOKEN_URL).is_empty());
    assert_eq!(harness.at(SEND_URL)[0].header("x-acme-access-token"), None);
}

#[tokio::test(start_paused = true)]
async fn caches_are_per_installation() {
    let harness = harness(healthy_vendor("7200")).await;
    harness.transport.execute(plan()).await.unwrap();
    let mut other = plan();
    other.installation_id = "inst-2".to_string();
    // inst-2's vendor token is TOKEN-2, which the healthy vendor accepts.
    harness.transport.execute(other).await.unwrap();
    assert_eq!(harness.at(TOKEN_URL).len(), 2);
}

mod redaction {
    use super::*;
    use std::io::Write;

    #[derive(Clone, Default)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
        type Writer = LogBuffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tokens_secrets_and_bodies_never_reach_logs_errors_or_debug_output() {
        let logs = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(logs.clone())
            .finish();
        let body = async {
            let mut surfaces: Vec<String> = Vec::new();
            // Success path.
            let ok = harness(healthy_vendor("7200")).await;
            let token = ok
                .exchange
                .exchanged_token(
                    "acme-messenger-token",
                    "inst-1",
                    &source(),
                    TokenRefresh::IfStale,
                )
                .await
                .unwrap();
            surfaces.push(format!("{token:?}"));
            surfaces.push(format!("{:?}", ok.exchange));
            surfaces.push(format!("{:?}", source()));
            let response = ok.transport.execute(plan()).await.unwrap();
            surfaces.push(format!("{response:?}"));

            // Failure paths with hostile bodies that echo secrets back.
            for step in [
                respond(
                    401,
                    r#"{"echo":"TOKEN-LEAK-CANARY APP-SECRET-SENTINEL-2222"}"#,
                ),
                respond(503, r#"{"echo":"TOKEN-LEAK-CANARY"}"#),
                respond(
                    200,
                    r#"{"accessToken":"TOKEN-LEAK-CANARY\n","expireIn":7200}"#,
                ),
                respond(302, r#"{"echo":"TOKEN-LEAK-CANARY"}"#),
                Step::Fail,
            ] {
                let failing = harness(move |request, _| {
                    if request.url == TOKEN_URL {
                        step.clone()
                    } else {
                        respond(200, "{}")
                    }
                })
                .await;
                let error = failing.transport.execute(plan()).await.unwrap_err();
                surfaces.push(format!("{error} | {error:?}"));
            }

            let captured = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
            surfaces.push(captured);
            for surface in &surfaces {
                for secret in ["TOKEN-1", "TOKEN-LEAK-CANARY", APP_KEY, APP_SECRET] {
                    assert!(
                        !surface.contains(secret),
                        "`{secret}` leaked into: {surface}"
                    );
                }
            }
        };
        tracing::instrument::WithSubscriber::with_subscriber(body, subscriber).await;
    }
}

#[cfg(feature = "test-support")]
#[tokio::test(start_paused = true)]
async fn the_bridged_port_forwards_token_exchange_to_its_fallback() {
    use crate::channel_egress::BridgedChannelEgressCredentials;
    let harness = harness(healthy_vendor("7200")).await;
    let bridged = BridgedChannelEgressCredentials::new(harness.exchange.clone());
    let token = bridged
        .exchanged_token(
            "acme-messenger-token",
            "inst-1",
            &source(),
            TokenRefresh::IfStale,
        )
        .await
        .unwrap();
    assert_eq!(token.generation, 1);
    assert_eq!(harness.at(TOKEN_URL).len(), 1);
}
