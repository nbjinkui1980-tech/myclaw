//! Channel egress transport: executes policy-approved channel vendor calls
//! (`ironclaw_extension_host::egress::ApprovedChannelEgress`) over the host
//! runtime HTTP egress — secret-material resolution, declared credential
//! injection (header / query / path placeholder), SSRF-safe transport with
//! the network policy pinned to the approved host, and response caps.
//!
//! Policy (allowlisting, header screening, handle equality) already ran in
//! `ironclaw_extension_host`; this module only resolves material and drives
//! the transport. Adapters never see secret bytes.
//!
//! A target that declares `[channel.egress.credential_source]` gets its token
//! from [`token_exchange::TokenExchangeEgressCredentials`] instead of a stored
//! secret: exchanged at the declared endpoint, held in memory only, injected
//! into the declared header, replaced once and the request resent once after a
//! 401. 5xx, 429 and timeouts are never retried. See that module for the cache
//! semantics, error mapping, and the residual copies on the shared response path.

pub mod token_exchange;

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_extension_contracts::tool_adapter::{RestrictedEgressError, RestrictedEgressResponse};
use ironclaw_extension_host::egress::{
    ApprovedChannelEgress, ApprovedCredentialSource, ChannelEgressTransport,
};
use ironclaw_host_api::{
    action::{NetworkPolicy, NetworkScheme, NetworkTargetPattern},
    http::{RuntimeHttpEgressReasonCode, RuntimeHttpEgressRequest},
    ids::{CapabilityId, ExtensionId, InvocationId, SecretHandle},
    resource::ResourceScope,
    runtime::{RuntimeKind, TrustClass},
};
use ironclaw_host_runtime::{
    HostRuntimeCredentialMaterial, HostRuntimeHttpEgressPort, HostRuntimeHttpEgressRequest,
};
use ironclaw_secrets::SecretMaterial;

/// Fixed capability id channel vendor calls are attributed to in egress
/// events/audit (mirrors the retiring per-vendor egress capability ids).
const CHANNEL_EGRESS_CAPABILITY_ID: &str = "channel.egress";

/// Resolves secret material for a channel-declared credential handle.
///
/// The generic implementation reads the scoped secret store (where
/// `[channel.config]` secret fields are stored under their handles); bridges
/// for legacy per-vendor setup storage implement the same port until their
/// storage migrates (P6).
#[async_trait]
pub trait ChannelEgressCredentialsPort: Send + Sync {
    async fn channel_secret(
        &self,
        extension_id: &str,
        installation_id: &str,
        handle: &SecretHandle,
    ) -> Result<Option<SecretMaterial>, ChannelEgressCredentialError>;

    /// The exchanged, in-memory-only token for a declared credential source.
    ///
    /// Only [`token_exchange::TokenExchangeEgressCredentials`] answers this; a
    /// port without it fails closed, so a source declared on a deployment that
    /// did not wire the decorator never reaches the network unauthenticated.
    /// Implementations that wrap another port must forward this method.
    async fn exchanged_token(
        &self,
        _extension_id: &str,
        _installation_id: &str,
        _source: &ApprovedCredentialSource,
        _refresh: TokenRefresh,
    ) -> Result<ExchangedToken, ChannelEgressCredentialError> {
        Err(ChannelEgressCredentialError::TokenSourceUnavailable)
    }
}

/// Whether a caller accepts a cached token or demands a replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRefresh {
    /// Reuse the cached token until its refresh time.
    IfStale,
    /// The request that used `generation` was rejected: drop that token (only
    /// if it is still the cached one) and exchange again.
    Invalidate { generation: u64 },
}

/// A token for one outbound request. `generation` identifies which cached
/// token it came from, so a rejection invalidates only that token. Debug never
/// shows the material.
pub struct ExchangedToken {
    pub material: SecretMaterial,
    pub generation: u64,
}

impl std::fmt::Debug for ExchangedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangedToken")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// Typed credential-resolution failures (never carry secret material).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChannelEgressCredentialError {
    #[error("channel credential backend unavailable")]
    Unavailable,
    /// No decorator in this port chain can exchange tokens.
    #[error("channel token source unavailable")]
    TokenSourceUnavailable,
    /// The token endpoint refused the app credentials (401/403) or they are
    /// not configured.
    #[error("channel token exchange rejected the application credentials")]
    ExchangeRejected,
    /// A transient exchange failure: timeout, network error, 408/429/5xx, or
    /// an unusable response.
    #[error("channel token exchange unavailable")]
    ExchangeUnavailable,
    /// A permanent declaration problem: policy denial, redirect, other status.
    #[error("channel token exchange is misdeclared")]
    ExchangeMisdeclared,
}

/// Generic credentials port over the scoped secret store.
#[cfg(test)]
pub struct SecretStoreChannelEgressCredentials {
    store: Arc<dyn ironclaw_secrets::SecretStorePort>,
    scope_template: ResourceScope,
}

#[cfg(test)]
impl SecretStoreChannelEgressCredentials {
    pub fn new(
        store: Arc<dyn ironclaw_secrets::SecretStorePort>,
        scope_template: ResourceScope,
    ) -> Self {
        Self {
            store,
            scope_template,
        }
    }
}

#[async_trait]
#[cfg(test)]
impl ChannelEgressCredentialsPort for SecretStoreChannelEgressCredentials {
    async fn channel_secret(
        &self,
        _extension_id: &str,
        _installation_id: &str,
        handle: &SecretHandle,
    ) -> Result<Option<SecretMaterial>, ChannelEgressCredentialError> {
        let lease = match self.store.lease_once(&self.scope_template, handle).await {
            Ok(lease) => lease,
            Err(_) => return Ok(None),
        };
        match self.store.consume(&self.scope_template, lease.id).await {
            Ok(material) => Ok(Some(material)),
            Err(_) => Err(ChannelEgressCredentialError::Unavailable),
        }
    }
}

/// Production credential bridge over the same effective configuration
/// resolver used by setup, OAuth, activation, pairing, and ingress.
pub struct ChannelConfigEgressCredentials {
    channel_config: Arc<ironclaw_extension_host::ChannelConfigService>,
}

impl ChannelConfigEgressCredentials {
    pub fn new(channel_config: Arc<ironclaw_extension_host::ChannelConfigService>) -> Self {
        Self { channel_config }
    }
}

#[async_trait]
impl ChannelEgressCredentialsPort for ChannelConfigEgressCredentials {
    async fn channel_secret(
        &self,
        extension_id: &str,
        _installation_id: &str,
        handle: &SecretHandle,
    ) -> Result<Option<SecretMaterial>, ChannelEgressCredentialError> {
        let extension_id = ExtensionId::new(extension_id)
            .map_err(|_| ChannelEgressCredentialError::Unavailable)?;
        self.channel_config
            .secret_material(&extension_id, handle)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "effective channel egress credential unavailable");
                ChannelEgressCredentialError::Unavailable
            })
    }
}

/// Wraps the generic scoped-store credentials port with a registration seam
/// that integration proofs use to inject a static `(extension, handle) →
/// material` mapping ahead of the store — standing in for `[channel.config]`
/// secret storage until the configure surface lands (P6/H). The registration
/// mechanism (`bridges` + [`register`](Self::register)) is `test-support`
/// only; a production build never registers a bridge and resolves straight
/// through `fallback`.
#[cfg(feature = "test-support")]
pub struct BridgedChannelEgressCredentials {
    bridges: std::sync::RwLock<Vec<Arc<dyn ChannelEgressCredentialsPort>>>,
    fallback: Arc<dyn ChannelEgressCredentialsPort>,
}

#[cfg(feature = "test-support")]
impl BridgedChannelEgressCredentials {
    pub fn new(fallback: Arc<dyn ChannelEgressCredentialsPort>) -> Self {
        Self {
            bridges: std::sync::RwLock::new(Vec::new()),
            fallback,
        }
    }

    pub fn register(&self, bridge: Arc<dyn ChannelEgressCredentialsPort>) {
        self.bridges
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(bridge);
    }
}

#[cfg(feature = "test-support")]
#[async_trait]
impl ChannelEgressCredentialsPort for BridgedChannelEgressCredentials {
    async fn channel_secret(
        &self,
        extension_id: &str,
        installation_id: &str,
        handle: &SecretHandle,
    ) -> Result<Option<SecretMaterial>, ChannelEgressCredentialError> {
        let bridges: Vec<Arc<dyn ChannelEgressCredentialsPort>> = self
            .bridges
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        for bridge in bridges {
            if let Some(material) = bridge
                .channel_secret(extension_id, installation_id, handle)
                .await?
            {
                return Ok(Some(material));
            }
        }
        self.fallback
            .channel_secret(extension_id, installation_id, handle)
            .await
    }

    async fn exchanged_token(
        &self,
        extension_id: &str,
        installation_id: &str,
        source: &ApprovedCredentialSource,
        refresh: TokenRefresh,
    ) -> Result<ExchangedToken, ChannelEgressCredentialError> {
        self.fallback
            .exchanged_token(extension_id, installation_id, source, refresh)
            .await
    }
}

/// Fixed `(extension_id, handle) → material` mapping, registered as a bridge
/// by integration proofs standing in for `[channel.config]` secret storage
/// until the configure surface lands (P6/H). Test-support only.
#[cfg(feature = "test-support")]
pub struct StaticChannelEgressCredentials {
    entries: Vec<(String, String, SecretMaterial)>,
}

#[cfg(feature = "test-support")]
impl StaticChannelEgressCredentials {
    pub fn new(entries: Vec<(String, String, SecretMaterial)>) -> Self {
        Self { entries }
    }
}

#[cfg(feature = "test-support")]
#[async_trait]
impl ChannelEgressCredentialsPort for StaticChannelEgressCredentials {
    async fn channel_secret(
        &self,
        extension_id: &str,
        _installation_id: &str,
        handle: &SecretHandle,
    ) -> Result<Option<SecretMaterial>, ChannelEgressCredentialError> {
        Ok(self
            .entries
            .iter()
            .find(|(extension, entry_handle, _)| {
                extension == extension_id && entry_handle == handle.as_str()
            })
            .map(|(_, _, material)| material.clone()))
    }
}

/// The production [`ChannelEgressTransport`]: host runtime egress with the
/// network policy pinned to the approved host.
pub struct HostRuntimeChannelEgressTransport {
    host_egress: HostRuntimeHttpEgressPort,
    credentials: Arc<dyn ChannelEgressCredentialsPort>,
    scope_template: ResourceScope,
}

impl HostRuntimeChannelEgressTransport {
    pub fn new(
        host_egress: HostRuntimeHttpEgressPort,
        credentials: Arc<dyn ChannelEgressCredentialsPort>,
        scope_template: ResourceScope,
    ) -> Self {
        Self {
            host_egress,
            credentials,
            scope_template,
        }
    }

    fn request_scope(&self) -> ResourceScope {
        let mut scope = self.scope_template.clone();
        scope.invocation_id = InvocationId::new();
        scope
    }
}

#[async_trait]
impl ChannelEgressTransport for HostRuntimeChannelEgressTransport {
    async fn execute(
        &self,
        approved: ApprovedChannelEgress,
    ) -> Result<RestrictedEgressResponse, RestrictedEgressError> {
        let Some(source) = approved.credential_source.clone() else {
            return self.dispatch(&approved, None).await;
        };
        let token = self
            .credentials
            .exchanged_token(
                &approved.extension_id,
                &approved.installation_id,
                &source,
                TokenRefresh::IfStale,
            )
            .await
            .map_err(|error| token_exchange::map_exchange_error(error, &source))?;
        let generation = token.generation;
        let response = self.dispatch(&approved, Some(token)).await?;
        // Only an explicit 401 means the token was refused. 5xx, 429, and
        // timeouts are never retried: the request may already have had its
        // effect, and a second send would repeat it.
        if response.status != 401 {
            return Ok(response);
        }
        let token = self
            .credentials
            .exchanged_token(
                &approved.extension_id,
                &approved.installation_id,
                &source,
                TokenRefresh::Invalidate { generation },
            )
            .await
            .map_err(|error| token_exchange::map_exchange_error(error, &source))?;
        // One retry, no more: whatever this answers is returned as-is.
        self.dispatch(&approved, Some(token)).await
    }
}

impl HostRuntimeChannelEgressTransport {
    /// Resolve the stored credentials, add the exchanged token if there is one,
    /// and drive one request through the host runtime egress.
    async fn dispatch(
        &self,
        approved: &ApprovedChannelEgress,
        token: Option<ExchangedToken>,
    ) -> Result<RestrictedEgressResponse, RestrictedEgressError> {
        let extension_id = ExtensionId::new(&approved.extension_id).map_err(|_| {
            RestrictedEgressError::Transport {
                reason: "invalid extension id for channel egress".to_string(),
            }
        })?;
        let capability_id = CapabilityId::new(CHANNEL_EGRESS_CAPABILITY_ID).map_err(|_| {
            RestrictedEgressError::Transport {
                reason: "invalid channel egress capability id".to_string(),
            }
        })?;

        let mut credentials = Vec::new();
        // The primary declared credential plus every declared body credential
        // this call opted into resolve through the same port and ride the
        // same host-runtime injection path; each is required, fail-closed.
        // With an exchange source the primary credential is the token, not a
        // stored secret, so it is injected from the exchanged material below.
        let stored_primary = approved
            .credential
            .iter()
            .filter(|_| approved.credential_source.is_none());
        for credential in stored_primary.chain(approved.body_credentials.iter()) {
            let material = self
                .credentials
                .channel_secret(
                    &approved.extension_id,
                    &approved.installation_id,
                    &credential.handle,
                )
                .await
                .map_err(|error| RestrictedEgressError::Transport {
                    reason: error.to_string(),
                })?;
            let Some(material) = material else {
                return Err(RestrictedEgressError::AuthRequired {
                    required_secrets: vec![credential.handle.clone()],
                    credential_requirements: Vec::new(),
                });
            };
            credentials.push(HostRuntimeCredentialMaterial {
                handle: credential.handle.clone(),
                material,
                target: credential_target_with_body_limit(
                    &credential.target,
                    approved.request_body_limit,
                ),
                required: true,
            });
        }
        if let Some(token) = token {
            let Some(declared) = &approved.credential else {
                return Err(RestrictedEgressError::PolicyDenied);
            };
            credentials.push(HostRuntimeCredentialMaterial {
                handle: declared.handle.clone(),
                material: token.material,
                target: declared.target.clone(),
                required: true,
            });
        }

        let response = self
            .host_egress
            .execute(HostRuntimeHttpEgressRequest {
                extension_id,
                trust: TrustClass::System,
                request: RuntimeHttpEgressRequest {
                    runtime: RuntimeKind::FirstParty,
                    scope: self.request_scope(),
                    capability_id,
                    method: approved.method,
                    url: approved.url.clone(),
                    headers: approved.headers.clone(),
                    body: approved.body.clone(),
                    network_policy: NetworkPolicy {
                        allowed_targets: vec![NetworkTargetPattern {
                            scheme: Some(NetworkScheme::Https),
                            host_pattern: approved.host.clone(),
                            port: None,
                        }],
                        deny_private_ip_ranges: true,
                        max_egress_bytes: None,
                    },
                    credential_injections: Vec::new(),
                    response_body_limit: Some(approved.response_body_limit),
                    save_body_to: None,
                    timeout_ms: Some(u32::try_from(approved.timeout_ms).unwrap_or(u32::MAX)),
                },
                credentials,
            })
            .await
            .map_err(map_runtime_http_error)?;

        Ok(RestrictedEgressResponse {
            retry_after: retry_after_hint(&response.headers),
            status: response.status,
            body: response.body,
        })
    }
}

/// The longest `Retry-After` a provider may park a publisher for. A hostile
/// or misconfigured provider sending an enormous value would otherwise stall
/// a reply indefinitely; anything above the cap is clamped to it.
const RETRY_AFTER_CAP: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Parse the delta-seconds form of `Retry-After` (RFC 9110 §10.2.3) into the
/// one typed response-header hint adapters may see. The HTTP-date form is
/// deliberately not parsed: it needs a clock the adapter cannot verify, and
/// every rate-limiting provider this host talks to sends delta-seconds.
fn retry_after_hint(headers: &[(String, String)]) -> Option<std::time::Duration> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.trim().parse::<u64>().ok())
        .map(|seconds| std::time::Duration::from_secs(seconds).min(RETRY_AFTER_CAP))
}

fn credential_target_with_body_limit(
    target: &ironclaw_host_api::http::RuntimeCredentialTarget,
    request_body_limit: Option<u64>,
) -> ironclaw_host_api::http::RuntimeCredentialTarget {
    match target {
        ironclaw_host_api::http::RuntimeCredentialTarget::BodyJsonPointer { pointer, .. } => {
            ironclaw_host_api::http::RuntimeCredentialTarget::BodyJsonPointer {
                pointer: pointer.clone(),
                post_injection_body_limit_bytes: request_body_limit,
            }
        }
        _ => target.clone(),
    }
}

fn map_runtime_http_error(
    error: ironclaw_host_api::http::RuntimeHttpEgressError,
) -> RestrictedEgressError {
    match error.reason_code() {
        RuntimeHttpEgressReasonCode::PolicyDenied | RuntimeHttpEgressReasonCode::RequestDenied => {
            RestrictedEgressError::PolicyDenied
        }
        RuntimeHttpEgressReasonCode::ResponseBodyLimitExceeded => {
            RestrictedEgressError::ResponseTooLarge
        }
        RuntimeHttpEgressReasonCode::CredentialUnavailable => RestrictedEgressError::AuthRequired {
            required_secrets: Vec::new(),
            credential_requirements: Vec::new(),
        },
        RuntimeHttpEgressReasonCode::NetworkError | RuntimeHttpEgressReasonCode::ResponseError => {
            RestrictedEgressError::Transport {
                reason: error.stable_runtime_reason().to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use ironclaw_authorization::GrantAuthorizer;
    use ironclaw_extension_host::egress::{ApprovedChannelCredential, ApprovedChannelEgress};
    use ironclaw_extension_registry::ExtensionRegistry;
    use ironclaw_filesystem::DiskFilesystem;
    use ironclaw_host_api::{
        action::NetworkMethod,
        http::RuntimeCredentialTarget,
        ids::{InvocationId, UserId},
    };
    use ironclaw_host_runtime::{CapabilitySurfaceVersion, HostRuntimeServices};
    use ironclaw_network::{
        NetworkHttpEgress, NetworkHttpError, NetworkHttpRequest, NetworkHttpResponse, NetworkUsage,
    };
    use ironclaw_processes::in_memory_backed_process_services;
    use ironclaw_resources::InMemoryResourceGovernor;
    use ironclaw_secrets::SecretStore;
    use secrecy::SecretString;

    use super::*;

    struct RecordingNetworkHttpEgress {
        requests: Arc<Mutex<Vec<NetworkHttpRequest>>>,
        response: Result<NetworkHttpResponse, NetworkHttpError>,
    }

    impl RecordingNetworkHttpEgress {
        fn with_response_headers(headers: Vec<(String, String)>) -> Self {
            let mut fake = Self::ok();
            if let Ok(response) = &mut fake.response {
                response.headers = headers;
            }
            fake
        }

        fn ok() -> Self {
            Self {
                requests: Arc::new(Mutex::new(Vec::new())),
                response: Ok(NetworkHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"{"ok":true}"#.to_vec(),
                    usage: NetworkUsage {
                        request_bytes: 0,
                        response_bytes: 11,
                        resolved_ip: None,
                    },
                }),
            }
        }

        fn requests(&self) -> Arc<Mutex<Vec<NetworkHttpRequest>>> {
            Arc::clone(&self.requests)
        }
    }

    #[async_trait]
    impl NetworkHttpEgress for RecordingNetworkHttpEgress {
        async fn execute(
            &self,
            request: NetworkHttpRequest,
        ) -> Result<NetworkHttpResponse, NetworkHttpError> {
            self.requests
                .lock()
                .expect("network HTTP requests lock")
                .push(request);
            self.response.clone()
        }
    }

    fn test_host_runtime_services() -> HostRuntimeServices<DiskFilesystem, InMemoryResourceGovernor>
    {
        HostRuntimeServices::new(
            Arc::new(ExtensionRegistry::new()),
            Arc::new(DiskFilesystem::new()),
            Arc::new(InMemoryResourceGovernor::new()),
            Arc::new(GrantAuthorizer::new()),
            in_memory_backed_process_services(),
            CapabilitySurfaceVersion::new("surface-v1").expect("surface version"),
        )
    }

    fn host_egress_port(
        network: RecordingNetworkHttpEgress,
    ) -> (
        HostRuntimeHttpEgressPort,
        Arc<Mutex<Vec<NetworkHttpRequest>>>,
    ) {
        let requests = network.requests();
        let services = test_host_runtime_services()
            .with_secret_store(Arc::new(SecretStore::ephemeral()))
            .try_with_host_http_egress(network)
            .expect("host HTTP egress should wire");
        let port = services
            .host_runtime_http_egress_port()
            .expect("host runtime HTTP egress port should be configured");
        (port, requests)
    }

    fn test_scope() -> ResourceScope {
        ResourceScope::local_default(
            UserId::new("channel-egress-user").unwrap(),
            InvocationId::new(),
        )
        .unwrap()
    }

    async fn seeded_credentials(
        scope: &ResourceScope,
        handle: &SecretHandle,
        value: &str,
    ) -> Arc<dyn ChannelEgressCredentialsPort> {
        use ironclaw_secrets::SecretStorePort as _;

        let store = Arc::new(SecretStore::ephemeral());
        store
            .put(
                scope.clone(),
                handle.clone(),
                SecretString::from(value.to_string()),
                None,
            )
            .await
            .expect("seed channel secret");
        Arc::new(SecretStoreChannelEgressCredentials::new(
            store as Arc<dyn ironclaw_secrets::SecretStorePort>,
            scope.clone(),
        ))
    }

    fn approved(
        url: &str,
        host: &str,
        credential: Option<ApprovedChannelCredential>,
    ) -> ApprovedChannelEgress {
        ApprovedChannelEgress {
            extension_id: "vendorx".to_string(),
            installation_id: "inst-1".to_string(),
            method: NetworkMethod::Post,
            url: url.to_string(),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: b"{}".to_vec(),
            host: host.to_string(),
            credential,
            body_credentials: Vec::new(),
            request_body_limit: None,
            response_body_limit: 64 * 1024,
            timeout_ms: 5_000,
            credential_source: None,
        }
    }

    #[tokio::test]
    async fn header_injection_reaches_the_network_request() {
        let scope = test_scope();
        let handle = SecretHandle::new("vendor_bot_token").unwrap();
        let credentials = seeded_credentials(&scope, &handle, "xoxb-secret-token").await;
        let (port, requests) = host_egress_port(RecordingNetworkHttpEgress::ok());
        let transport = HostRuntimeChannelEgressTransport::new(port, credentials, scope);

        let response = transport
            .execute(approved(
                "https://vendor.example/api/chat.postMessage",
                "vendor.example",
                Some(ApprovedChannelCredential {
                    handle: handle.clone(),
                    target: RuntimeCredentialTarget::Header {
                        name: "authorization".to_string(),
                        prefix: Some("Bearer ".to_string()),
                    },
                }),
            ))
            .await
            .expect("transport executes");
        assert_eq!(response.status, 200);

        let recorded = requests.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].url,
            "https://vendor.example/api/chat.postMessage"
        );
        let authorization = recorded[0]
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .expect("authorization header injected host-side");
        assert_eq!(authorization.1, "Bearer xoxb-secret-token");
        // The network policy is pinned to the approved host with private-IP
        // denial.
        assert!(recorded[0].policy.deny_private_ip_ranges);
        assert_eq!(recorded[0].policy.allowed_targets.len(), 1);
        assert_eq!(
            recorded[0].policy.allowed_targets[0].host_pattern,
            "vendor.example"
        );
        assert_eq!(recorded[0].response_body_limit, Some(64 * 1024));
    }

    #[tokio::test]
    async fn path_placeholder_injection_substitutes_the_secret_host_side() {
        let scope = test_scope();
        let handle = SecretHandle::new("vendor_bot_token").unwrap();
        let credentials = seeded_credentials(&scope, &handle, "123456:telegram-token").await;
        let (port, requests) = host_egress_port(RecordingNetworkHttpEgress::ok());
        let transport = HostRuntimeChannelEgressTransport::new(port, credentials, scope);

        transport
            .execute(approved(
                "https://vendor.example/bot{token}/sendMessage",
                "vendor.example",
                Some(ApprovedChannelCredential {
                    handle,
                    target: RuntimeCredentialTarget::PathPlaceholder {
                        placeholder: "token".to_string(),
                    },
                }),
            ))
            .await
            .expect("transport executes");

        let recorded = requests.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].url, "https://vendor.example/bot123456:telegram-token/sendMessage",
            "the placeholder is substituted host-side; the adapter never saw the token"
        );
    }

    #[tokio::test]
    async fn body_json_pointer_credential_is_resolved_into_the_wire_body() {
        let scope = test_scope();
        let handle = SecretHandle::new("vendor_webhook_secret").unwrap();
        let credentials = seeded_credentials(&scope, &handle, "wh-sentinel-secret").await;
        let (port, requests) = host_egress_port(RecordingNetworkHttpEgress::ok());
        let transport = HostRuntimeChannelEgressTransport::new(port, credentials, scope);

        let mut plan = approved(
            "https://vendor.example/api/setWebhook",
            "vendor.example",
            None,
        );
        plan.body = br#"{"url":"https://hooks.example/updates"}"#.to_vec();
        plan.body_credentials = vec![ApprovedChannelCredential {
            handle,
            target: RuntimeCredentialTarget::BodyJsonPointer {
                pointer: "/secret_token".to_string(),
                post_injection_body_limit_bytes: None,
            },
        }];
        transport.execute(plan).await.expect("transport executes");

        let recorded = requests.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&recorded[0].body).unwrap();
        assert_eq!(
            body["secret_token"], "wh-sentinel-secret",
            "the resolved secret VALUE is inserted host-side; the adapter never saw it"
        );
        assert_eq!(body["url"], "https://hooks.example/updates");
    }

    #[tokio::test]
    async fn body_json_pointer_credential_cannot_exceed_the_approved_request_body_limit() {
        let scope = test_scope();
        let handle = SecretHandle::new("vendor_webhook_secret").unwrap();
        let credentials = seeded_credentials(&scope, &handle, "secret-expands-the-body").await;
        let (port, requests) = host_egress_port(RecordingNetworkHttpEgress::ok());
        let transport = HostRuntimeChannelEgressTransport::new(port, credentials, scope);

        let mut plan = approved(
            "https://vendor.example/api/setWebhook",
            "vendor.example",
            None,
        );
        plan.body = b"{}".to_vec();
        plan.request_body_limit = Some(16);
        plan.body_credentials = vec![ApprovedChannelCredential {
            handle,
            target: RuntimeCredentialTarget::BodyJsonPointer {
                pointer: "/secret_token".to_string(),
                post_injection_body_limit_bytes: None,
            },
        }];

        let error = transport
            .execute(plan)
            .await
            .expect_err("post-injection body above the manifest cap must fail closed");
        assert!(matches!(error, RestrictedEgressError::PolicyDenied));
        assert!(
            requests.lock().unwrap().is_empty(),
            "an oversized post-injection body must never reach network transport"
        );
    }

    #[tokio::test]
    async fn missing_secret_material_fails_closed_as_auth_required() {
        let scope = test_scope();
        let handle = SecretHandle::new("vendor_bot_token").unwrap();
        // Credentials port over an EMPTY store: no material seeded.
        let credentials: Arc<dyn ChannelEgressCredentialsPort> =
            Arc::new(SecretStoreChannelEgressCredentials::new(
                Arc::new(SecretStore::ephemeral()) as Arc<dyn ironclaw_secrets::SecretStorePort>,
                scope.clone(),
            ));
        let (port, requests) = host_egress_port(RecordingNetworkHttpEgress::ok());
        let transport = HostRuntimeChannelEgressTransport::new(port, credentials, scope);

        let error = transport
            .execute(approved(
                "https://vendor.example/api/x",
                "vendor.example",
                Some(ApprovedChannelCredential {
                    handle: handle.clone(),
                    target: RuntimeCredentialTarget::Header {
                        name: "authorization".to_string(),
                        prefix: Some("Bearer ".to_string()),
                    },
                }),
            ))
            .await
            .expect_err("missing material fails closed");
        match error {
            RestrictedEgressError::AuthRequired {
                required_secrets, ..
            } => assert_eq!(required_secrets, vec![handle]),
            other => panic!("expected AuthRequired, got {other:?}"),
        }
        assert!(
            requests.lock().unwrap().is_empty(),
            "no network activity without credential material"
        );
    }

    #[test]
    fn retry_after_hint_parses_delta_seconds_case_insensitively_and_caps() {
        let header = |name: &str, value: &str| vec![(name.to_string(), value.to_string())];
        assert_eq!(
            retry_after_hint(&header("Retry-After", "3")),
            Some(std::time::Duration::from_secs(3))
        );
        assert_eq!(
            retry_after_hint(&header("retry-after", " 12 ")),
            Some(std::time::Duration::from_secs(12))
        );
        assert_eq!(
            retry_after_hint(&header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT")),
            None,
            "the HTTP-date form is deliberately not parsed"
        );
        assert_eq!(
            retry_after_hint(&header("Retry-After", "999999999")),
            Some(RETRY_AFTER_CAP),
            "a hostile value is clamped, never honoured"
        );
        assert_eq!(retry_after_hint(&[]), None);
    }

    /// The caller-level proof for the retry hint: `execute` transfers the
    /// provider's `Retry-After` response header into
    /// `RestrictedEgressResponse::retry_after`, capped — not just the parser
    /// helper in isolation.
    #[tokio::test]
    async fn execute_carries_the_capped_retry_after_hint_onto_the_response() {
        let scope = test_scope();
        let (port, _requests) =
            host_egress_port(RecordingNetworkHttpEgress::with_response_headers(vec![(
                "Retry-After".to_string(),
                "7".to_string(),
            )]));
        let credentials = seeded_credentials(
            &scope,
            &SecretHandle::new("vendor_bot_token").unwrap(),
            "unused",
        )
        .await;
        let transport = HostRuntimeChannelEgressTransport::new(port, credentials, scope);

        let response = transport
            .execute(approved(
                "https://vendor.example/api/chat.postMessage",
                "vendor.example",
                None,
            ))
            .await
            .expect("transport executes");
        assert_eq!(
            response.retry_after,
            Some(std::time::Duration::from_secs(7)),
            "the provider's Retry-After rides the restricted-egress response"
        );
    }
}
