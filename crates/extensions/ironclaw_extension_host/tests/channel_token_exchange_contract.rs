//! Token exchange through a REAL `ExtensionHost` and ingress router (milestone
//! 1b Task 11, host path): a signed webhook reaches the adapter, the adapter
//! sends one message naming the declared token handle, and the host exchanges,
//! caches, and injects the token on the vendor request. Assertions are made on
//! what the scripted network saw and on what the adapter was allowed to see.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use ironclaw_authorization::GrantAuthorizer;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelError, ChannelIngress, ChannelSurfaces, InboundOutcome, VerifiedInbound,
};
use ironclaw_extension_contracts::state::InstallationState;
use ironclaw_extension_contracts::tool_adapter::{
    RestrictedEgress, RestrictedEgressRequest, RestrictedEgressResponse,
};
use ironclaw_extension_host::channel_egress::{
    HostRuntimeChannelEgressTransport, StaticChannelEgressCredentials,
    token_exchange::TokenExchangeEgressCredentials,
};
use ironclaw_extension_host::egress::TransportBackedEgressFactory;
use ironclaw_extension_host::ingress::{
    ExtensionIngressRouter, ExtensionIngressRouterDeps, InboundAdmission, InboundAdmissionAck,
    InboundSink, InboundSinkError, IngressConfigurationPort, IngressPortError, IngressRequest,
    IngressRouterConfig, IngressSecretsPort, ReplyContextKey, ReplyContextStore,
    VerificationCandidate,
};
use ironclaw_extension_host::test_support::resolve_manifest_toml;
use ironclaw_extension_host::{
    ExtensionBindings, ExtensionEntrypoint, ExtensionHost, ExtensionHostDeps, ExtensionLoader,
    FilesystemInboundBatchStore, InstallationRecord, InstallationRecordStore, LoadContext,
    LoadedExtension, RehydratedInstallationRecordStore,
};
use ironclaw_extension_registry::ExtensionRegistry;
use ironclaw_filesystem::{DiskFilesystem, InMemoryBackend};
use ironclaw_host_api::action::NetworkMethod;
use ironclaw_host_api::ids::{InvocationId, SecretHandle, TenantId, UserId};
use ironclaw_host_api::resource::ResourceScope;
use ironclaw_host_runtime::{CapabilitySurfaceVersion, HostRuntimeServices};
use ironclaw_network::{
    NetworkHttpEgress, NetworkHttpError, NetworkHttpRequest, NetworkHttpResponse, NetworkUsage,
};
use ironclaw_processes::in_memory_backed_process_services;
use ironclaw_resources::InMemoryResourceGovernor;
use ironclaw_secrets::SecretStore;
use secrecy::SecretString;
use sha2::Sha256;

const EXTENSION_ID: &str = "acme-chat";
const INSTALLATION_ID: &str = "acme-chat-install";
const SIGNING_SECRET: &[u8] = b"contract-signing-secret";
const TOKEN_URL: &str = "https://auth.acme.example/v1/oauth/token";
const SEND_URL: &str = "https://api.acme.example/v1/messages";

const MANIFEST_HEAD: &str = r#"
schema_version = "reborn.extension_manifest.v3"
id = "acme-chat"
name = "Acme Chat"
version = "0.1.0"
description = "token exchange host-path fixture"
trust = "third_party"
[runtime]
kind = "wasm"
module = "wasm/acme_chat.wasm"
[channel]
id = "messages"
display_name = "Acme chat"
conversation_model = "continuous"
[channel.ingress]
route_suffix = "events"
method = "post"
body_limit_bytes = 512
[channel.ingress.verification]
kind = "hmac_sha256"
secret_handle = "acme_chat_signing_secret"
signature_header = "X-Acme-Signature"
signature_prefix = "v0="
signature_encoding = "hex"
timestamp_header = "X-Acme-Request-Timestamp"
max_age_seconds = 300
signed_payload = [
  { literal = "v0:" },
  { header = "X-Acme-Request-Timestamp" },
  { literal = ":" },
  { body = true },
]
[admin_configuration]
group_id = "acme.chat"
display_name = "Acme Chat channel"
fields = [
  { handle = "acme_chat_signing_secret", label = "Signing secret", secret = true },
  { handle = "acme_app_key", label = "App key", secret = true },
  { handle = "acme_app_secret", label = "App secret", secret = true },
]
[[channel.egress]]
scheme = "https"
host = "auth.acme.example"
methods = ["post"]
paths = ["/v1/oauth/token"]
[[channel.egress.body_credentials]]
handle = "acme_app_key"
pointer = "/appKey"
[[channel.egress.body_credentials]]
handle = "acme_app_secret"
pointer = "/appSecret"
[[channel.egress]]
scheme = "https"
host = "api.acme.example"
methods = ["post"]
paths = ["/v1/messages"]
"#;

const SOURCE_TAIL: &str = r#"
[channel.egress.credential_source]
handle = "acme_access_token"
exchange_host = "auth.acme.example"
token_pointer = "/accessToken"
expires_in_pointer = "/expireIn"
[channel.egress.credential_source.exchange]
method = "post"
path = "/v1/oauth/token"
body = { grantType = "client_credentials" }
body_credentials = ["acme_app_key", "acme_app_secret"]
[channel.egress.credential_source.header]
name = "x-acme-access-token"
"#;

fn manifest(with_source: bool) -> String {
    if with_source {
        format!("{MANIFEST_HEAD}{SOURCE_TAIL}")
    } else {
        MANIFEST_HEAD.to_string()
    }
}

// ── Scripted vendor network ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Seen {
    url: String,
    headers: Vec<(String, String)>,
    body: String,
}

struct ScriptedVendor {
    seen: Arc<Mutex<Vec<Seen>>>,
    issued: AtomicUsize,
}

#[async_trait]
impl NetworkHttpEgress for ScriptedVendor {
    async fn execute(
        &self,
        request: NetworkHttpRequest,
    ) -> Result<NetworkHttpResponse, NetworkHttpError> {
        let seen = Seen {
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: String::from_utf8_lossy(&request.body).to_string(),
        };
        let (status, body) = if request.url == TOKEN_URL {
            let n = self.issued.fetch_add(1, Ordering::SeqCst) + 1;
            (
                200,
                format!(r#"{{"accessToken":"HOST-TOKEN-{n}","expireIn":7200}}"#),
            )
        } else {
            (200, r#"{"ok":true}"#.to_string())
        };
        self.seen.lock().unwrap().push(seen);
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
}

// ── Adapter ─────────────────────────────────────────────────────────────────

/// What the adapter built and what the host handed back.
#[derive(Debug, Clone)]
struct AdapterRecord {
    request: RestrictedEgressRequest,
    response: Option<RestrictedEgressResponse>,
    error: Option<String>,
}

struct SendingAdapter {
    credential: Option<&'static str>,
    records: Arc<Mutex<Vec<AdapterRecord>>>,
}

#[async_trait]
impl ChannelIngress for SendingAdapter {
    async fn receive(
        &self,
        _request: VerifiedInbound<'_>,
        egress: &dyn RestrictedEgress,
    ) -> Result<InboundOutcome, ChannelError> {
        let request = RestrictedEgressRequest {
            method: NetworkMethod::Post,
            url: SEND_URL.to_string(),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: Some(br#"{"text":"hello"}"#.to_vec()),
            credential: self
                .credential
                .map(|handle| SecretHandle::new(handle).expect("handle")),
            body_credentials: Vec::new(),
        };
        let result = egress.send(request.clone()).await;
        self.records.lock().unwrap().push(AdapterRecord {
            request,
            response: result.as_ref().ok().cloned(),
            error: result.err().map(|error| format!("{error:?}")),
        });
        Ok(InboundOutcome::Ignore)
    }
}

struct FixedLoader {
    adapter: Arc<SendingAdapter>,
}

#[async_trait]
impl ExtensionLoader for FixedLoader {
    async fn load(
        &self,
        _ctx: &LoadContext,
    ) -> Result<LoadedExtension, ironclaw_extension_host::BindError> {
        struct Entry(Arc<SendingAdapter>);
        impl ExtensionEntrypoint for Entry {
            fn bind(
                &self,
                _ctx: ironclaw_extension_host::BindContext,
            ) -> Result<ExtensionBindings, ironclaw_extension_host::BindError> {
                Ok(ExtensionBindings {
                    tools: None,
                    channel: ChannelSurfaces::default()
                        .with_ingress(Arc::clone(&self.0) as Arc<dyn ChannelIngress>),
                    device_link: None,
                })
            }
        }
        Ok(LoadedExtension::new(Box::new(Entry(Arc::clone(
            &self.adapter,
        )))))
    }
}

// ── Minimal router ports ────────────────────────────────────────────────────

struct Secrets;
#[async_trait]
impl IngressSecretsPort for Secrets {
    async fn verification_candidates(
        &self,
        _extension_id: &str,
        _installation_id: &str,
        _handle: Option<&SecretHandle>,
    ) -> Result<Vec<VerificationCandidate>, IngressPortError> {
        Ok(vec![VerificationCandidate {
            installation_id: INSTALLATION_ID.to_string(),
            secret: SIGNING_SECRET.to_vec(),
        }])
    }
}

struct Config;
#[async_trait]
impl IngressConfigurationPort for Config {
    async fn non_secret_config(
        &self,
        _extension_id: &str,
        _installation_id: &str,
    ) -> Result<Vec<(String, String)>, IngressPortError> {
        Ok(Vec::new())
    }
}

struct Sink;
#[async_trait]
impl InboundSink for Sink {
    async fn admit(
        &self,
        _admission: InboundAdmission,
    ) -> Result<InboundAdmissionAck, InboundSinkError> {
        Ok(InboundAdmissionAck::Accepted)
    }
}

#[derive(Default)]
struct Replies(Mutex<Vec<(ReplyContextKey, Vec<u8>)>>);
#[async_trait]
impl ReplyContextStore for Replies {
    async fn put(&self, key: ReplyContextKey, context: Vec<u8>) -> Result<(), IngressPortError> {
        self.0.lock().unwrap().push((key, context));
        Ok(())
    }
    async fn get(&self, key: &ReplyContextKey) -> Result<Option<Vec<u8>>, IngressPortError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|(existing, _)| existing == key)
            .map(|(_, context)| context.clone()))
    }
}

// ── Harness ─────────────────────────────────────────────────────────────────

struct Harness {
    router: ExtensionIngressRouter,
    network: Arc<Mutex<Vec<Seen>>>,
    adapter: Arc<Mutex<Vec<AdapterRecord>>>,
}

impl Harness {
    fn at(&self, url: &str) -> Vec<Seen> {
        self.network
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.url == url)
            .cloned()
            .collect()
    }

    async fn deliver(&self) {
        let body = br#"{"text":"ping"}"#;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let mut mac = Hmac::<Sha256>::new_from_slice(SIGNING_SECRET).unwrap();
        mac.update(format!("v0:{timestamp}:").as_bytes());
        mac.update(body);
        let signature = format!(
            "v0={}",
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let response = self
            .router
            .handle(IngressRequest {
                method: "POST".to_string(),
                extension_id: EXTENSION_ID.to_string(),
                route_suffix: "events".to_string(),
                headers: vec![
                    ("X-Acme-Signature".to_string(), signature.into_bytes()),
                    (
                        "X-Acme-Request-Timestamp".to_string(),
                        timestamp.into_bytes(),
                    ),
                    ("Content-Type".to_string(), b"application/json".to_vec()),
                ],
                body: body.to_vec(),
            })
            .await;
        assert_eq!(response.status, 200);
    }
}

async fn harness(with_source: bool, credential: Option<&'static str>) -> Harness {
    let scope =
        ResourceScope::local_default(UserId::new("token-host").unwrap(), InvocationId::new())
            .unwrap();
    let network = Arc::new(Mutex::new(Vec::new()));
    let port = HostRuntimeServices::new(
        Arc::new(ExtensionRegistry::new()),
        Arc::new(DiskFilesystem::new()),
        Arc::new(InMemoryResourceGovernor::new()),
        Arc::new(GrantAuthorizer::new()),
        in_memory_backed_process_services(),
        CapabilitySurfaceVersion::new("surface-v1").unwrap(),
    )
    .with_secret_store(Arc::new(SecretStore::ephemeral()))
    .try_with_host_http_egress(ScriptedVendor {
        seen: Arc::clone(&network),
        issued: AtomicUsize::new(0),
    })
    .unwrap()
    .host_runtime_http_egress_port()
    .unwrap();
    let app_credentials = Arc::new(StaticChannelEgressCredentials::new(vec![
        (
            EXTENSION_ID.to_string(),
            "acme_app_key".to_string(),
            SecretString::from("HOST-APP-KEY".to_string()),
        ),
        (
            EXTENSION_ID.to_string(),
            "acme_app_secret".to_string(),
            SecretString::from("HOST-APP-SECRET".to_string()),
        ),
    ]));
    let credentials = Arc::new(TokenExchangeEgressCredentials::new(
        app_credentials,
        port.clone(),
        scope.clone(),
    ));
    let transport = Arc::new(HostRuntimeChannelEgressTransport::new(
        port,
        credentials,
        scope,
    ));
    let records = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(SendingAdapter {
        credential,
        records: Arc::clone(&records),
    });
    let host = Arc::new(
        ExtensionHost::new(ExtensionHostDeps {
            store: Arc::new(RehydratedInstallationRecordStore::default())
                as Arc<dyn InstallationRecordStore>,
            loader: Arc::new(FixedLoader { adapter }),
            drain: Arc::new(ironclaw_extension_host::test_support::RecordingDrain::default()),
            egress: Arc::new(TransportBackedEgressFactory::new(transport.clone())),
            reserved_capability_ids: Default::default(),
            reserved_ingress_routes: Default::default(),
            hook_deadline: Duration::from_secs(5),
            linked_sessions: ironclaw_extension_host::LinkedSessionStore::unavailable(),
            linked_accounts: Arc::new(ironclaw_extension_host::UnavailableLinkedAccountResolution),
            admin_secrets: None,
        })
        .await,
    );
    let router = ExtensionIngressRouter::new(
        host.snapshot_watch(),
        ExtensionIngressRouterDeps {
            secrets: Arc::new(Secrets),
            configuration: Arc::new(Config),
            sink: Arc::new(Sink),
            reply_context: Arc::new(Replies::default()),
            inbound_batches: Arc::new(
                FilesystemInboundBatchStore::new(
                    Arc::new(InMemoryBackend::new()),
                    TenantId::new("tenant-test").unwrap(),
                    UserId::new("user-test").unwrap(),
                )
                .unwrap(),
            ),
            channel_egress_transport: Some(transport),
        },
        IngressRouterConfig {
            request_deadline: Duration::from_secs(5),
            ..IngressRouterConfig::default()
        },
    );
    host.install(InstallationRecord {
        extension_id: EXTENSION_ID.to_string(),
        installation_id: INSTALLATION_ID.to_string(),
        state: InstallationState::Installed,
        resolved: Arc::new(resolve_manifest_toml(&manifest(with_source))),
        config: Vec::new(),
        last_error: None,
    })
    .await
    .expect("install");
    host.activate(EXTENSION_ID).await.expect("activate");
    Harness {
        router,
        network,
        adapter: records,
    }
}

#[tokio::test]
async fn the_host_exchanges_once_injects_the_header_and_hides_the_token_from_the_adapter() {
    let harness = harness(true, Some("acme_access_token")).await;
    harness.deliver().await;
    let exchanges = harness.at(TOKEN_URL);
    assert_eq!(exchanges.len(), 1);
    let exchange_body: serde_json::Value = serde_json::from_str(&exchanges[0].body).unwrap();
    assert_eq!(exchange_body["appKey"], "HOST-APP-KEY");
    assert_eq!(exchange_body["appSecret"], "HOST-APP-SECRET");
    let sends = harness.at(SEND_URL);
    assert_eq!(sends.len(), 1);
    let injected = sends[0]
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-acme-access-token"))
        .map(|(_, value)| value.as_str());
    assert_eq!(injected, Some("HOST-TOKEN-1"));

    // The adapter built the request without token bytes and got none back.
    let records = harness.adapter.lock().unwrap().clone();
    assert_eq!(records.len(), 1);
    let rendered = format!("{records:?}");
    for secret in ["HOST-TOKEN-1", "HOST-APP-KEY", "HOST-APP-SECRET"] {
        assert!(!rendered.contains(secret), "{secret} reached the adapter");
    }
    assert!(
        records[0]
            .request
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("x-acme-access-token"))
    );
    assert_eq!(records[0].response.as_ref().map(|r| r.status), Some(200));

    // A second webhook reuses the cached token.
    harness.deliver().await;
    assert_eq!(harness.at(TOKEN_URL).len(), 1);
    assert_eq!(harness.at(SEND_URL).len(), 2);
}

#[tokio::test]
async fn a_manifest_whose_exchange_endpoint_is_undeclared_never_installs() {
    let broken = manifest(true).replace(
        "exchange_host = \"auth.acme.example\"",
        "exchange_host = \"unlisted.acme.example\"",
    );
    let outcome = std::panic::catch_unwind(|| resolve_manifest_toml(&broken));
    assert!(
        outcome.is_err(),
        "descriptor validation must reject an undeclared exchange endpoint at parse"
    );
}

#[tokio::test]
async fn a_channel_without_a_source_delivers_with_zero_exchange_requests() {
    let harness = harness(false, None).await;
    harness.deliver().await;
    assert!(harness.at(TOKEN_URL).is_empty());
    assert_eq!(harness.at(SEND_URL).len(), 1);
    let records = harness.adapter.lock().unwrap().clone();
    assert_eq!(records[0].response.as_ref().map(|r| r.status), Some(200));
}

#[tokio::test]
async fn naming_the_token_handle_on_a_channel_without_a_source_is_rejected() {
    let harness = harness(false, Some("acme_access_token")).await;
    harness.deliver().await;
    assert!(harness.network.lock().unwrap().is_empty());
    let records = harness.adapter.lock().unwrap().clone();
    assert!(records[0].error.is_some());
}
