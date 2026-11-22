//! Host-side token exchange for channel egress (ADR 6.2 option B).
//!
//! [`TokenExchangeEgressCredentials`] decorates a [`ChannelEgressCredentialsPort`]
//! and answers [`ChannelEgressCredentialsPort::exchanged_token`]: it exchanges
//! the application credentials declared in a manifest's
//! `[channel.egress.credential_source]` for a short-lived token, keeps the token
//! **in memory only**, refreshes it ahead of expiry, and lets exactly one
//! exchange per installation and source be in flight.
//!
//! What this module guarantees about the token:
//!
//! - It is held in a [`SecretMaterial`] (zeroized on drop, redacted `Debug`), is
//!   never persisted, and is never placed in a store, event, log line, error,
//!   audit record, or status projection. Adapters never see it: the transport
//!   injects it into the outbound request at the moment of the call.
//! - The cache never assumes the server hands out a reusable token. A token is
//!   used until `refresh_at` and then replaced by a fresh exchange; a rejected
//!   token (401) is dropped and exchanged again. Nothing here depends on
//!   whether a repeated exchange returns the same token or on any vendor field
//!   name; the response pointers and the unit (seconds) come from the manifest.
//!
//! Residual copies, stated honestly: the token response travels the shared
//! HTTP response path. `ironclaw_network` accumulates it in a `Vec<u8>`,
//! `RuntimeHttpEgressResponse.body` carries it, and reqwest/hyper/rustls and
//! the kernel keep internal buffers; none of those are ours to scrub, and the
//! shared response type is deliberately unchanged (ADR revision approval "X").
//! The host-owned copies are scrubbed: the response body is wrapped in
//! `Zeroizing`, the token is moved out of the parsed tree into the cached
//! secret without a copy, and the parse tree itself is the one extra copy
//! (`serde_json::Value` leaves the other fields in place, not the token).
//!
//! The per-source mutex below serializes an in-memory cache only. It does not
//! guard a backend read-modify-write, so `.claude/rules/database.md`'s CAS rule
//! does not apply.

use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex as StdMutex, PoisonError},
    time::Duration,
};

use async_trait::async_trait;
use ironclaw_extension_contracts::tool_adapter::RestrictedEgressError;
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
use secrecy::SecretString;
use tokio::{sync::Mutex, time::Instant};
use zeroize::Zeroizing;

use super::{
    CHANNEL_EGRESS_CAPABILITY_ID, ChannelEgressCredentialError, ChannelEgressCredentialsPort,
    ExchangedToken, TokenRefresh,
};
use crate::egress::{ApprovedCredentialSource, CHANNEL_EGRESS_TIMEOUT_MS};

/// Lifetime assumed when the response carries no usable expiry.
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(300);
/// Shortest lifetime the cache will plan around, however small the server's.
pub const MIN_TOKEN_TTL: Duration = Duration::from_secs(60);
/// Longest lifetime the cache will plan around.
pub const MAX_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// The refresh margin is `min(MAX_REFRESH_MARGIN, ttl / REFRESH_MARGIN_DIVISOR)`.
pub const MAX_REFRESH_MARGIN: Duration = Duration::from_secs(300);
const REFRESH_MARGIN_DIVISOR: u32 = 5;
/// Cap on the token response body, whatever the exchange target declares.
pub const TOKEN_RESPONSE_LIMIT_BYTES: u64 = 16 * 1024;
/// Cached sources before the least recently used one is evicted.
const CACHE_CAPACITY: usize = 256;
/// Longest token the host will place in a header.
const MAX_TOKEN_BYTES: usize = 4096;

/// How long a cached token stays usable, from the exchange response.
///
/// `expires_in_secs` is the server's declared lifetime in seconds (a missing,
/// zero, or unparseable value falls back to [`DEFAULT_TOKEN_TTL`]); the result
/// is clamped to `[MIN_TOKEN_TTL, MAX_TOKEN_TTL]` and reduced by the refresh
/// margin so the token is replaced before the server stops honouring it.
pub fn refresh_after(expires_in_secs: Option<u64>) -> Duration {
    let ttl = match expires_in_secs {
        Some(secs) if secs > 0 => Duration::from_secs(secs),
        _ => DEFAULT_TOKEN_TTL,
    }
    .clamp(MIN_TOKEN_TTL, MAX_TOKEN_TTL);
    let margin = (ttl / REFRESH_MARGIN_DIVISOR).min(MAX_REFRESH_MARGIN);
    ttl - margin
}

/// `(extension, installation, handle, exchange URL)`. The URL keeps a token
/// exchanged for one declaration from serving a later, different declaration.
type CacheKey = (String, String, String, String);

struct CachedToken {
    material: SecretMaterial,
    refresh_at: Instant,
    generation: u64,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken").finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Slot {
    token: Option<CachedToken>,
    next_generation: u64,
}

/// The decorator. `channel_secret` delegates to the inner port; the exchange
/// resolves the app credentials through that same inner port.
pub struct TokenExchangeEgressCredentials {
    inner: Arc<dyn ChannelEgressCredentialsPort>,
    host_egress: HostRuntimeHttpEgressPort,
    scope_template: ResourceScope,
    slots: StdMutex<lru::LruCache<CacheKey, Arc<Mutex<Slot>>>>,
}

impl std::fmt::Debug for TokenExchangeEgressCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeEgressCredentials")
            .finish_non_exhaustive()
    }
}

impl TokenExchangeEgressCredentials {
    pub fn new(
        inner: Arc<dyn ChannelEgressCredentialsPort>,
        host_egress: HostRuntimeHttpEgressPort,
        scope_template: ResourceScope,
    ) -> Self {
        let capacity = NonZeroUsize::new(CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner,
            host_egress,
            scope_template,
            slots: StdMutex::new(lru::LruCache::new(capacity)),
        }
    }

    fn slot_for(&self, key: CacheKey) -> Arc<Mutex<Slot>> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = slots.get(&key) {
            return Arc::clone(slot);
        }
        let slot = Arc::new(Mutex::new(Slot::default()));
        slots.put(key, Arc::clone(&slot));
        slot
    }

    async fn exchange(
        &self,
        extension_id: &str,
        installation_id: &str,
        source: &ApprovedCredentialSource,
    ) -> Result<(SecretMaterial, Duration), ChannelEgressCredentialError> {
        use ChannelEgressCredentialError as Failure;
        let extension =
            ExtensionId::new(extension_id).map_err(|_invalid| Failure::ExchangeMisdeclared)?;
        let capability = CapabilityId::new(CHANNEL_EGRESS_CAPABILITY_ID)
            .map_err(|_invalid| Failure::ExchangeMisdeclared)?;
        let mut credentials = Vec::with_capacity(source.credentials.len());
        for credential in &source.credentials {
            let material = self
                .inner
                .channel_secret(extension_id, installation_id, &credential.handle)
                .await
                .map_err(|_backend| Failure::ExchangeUnavailable)?;
            // No stored app credential is a credential problem the operator can
            // fix, so it reads as a rejected exchange (AuthRequired upstream).
            let Some(material) = material else {
                return Err(Failure::ExchangeRejected);
            };
            credentials.push(HostRuntimeCredentialMaterial {
                handle: credential.handle.clone(),
                material,
                target: credential.target.clone(),
                required: true,
            });
        }
        let mut scope = self.scope_template.clone();
        scope.invocation_id = InvocationId::new();
        let response = self
            .host_egress
            .execute(HostRuntimeHttpEgressRequest {
                extension_id: extension,
                trust: TrustClass::System,
                request: RuntimeHttpEgressRequest {
                    runtime: RuntimeKind::FirstParty,
                    scope,
                    capability_id: capability,
                    method: source.method,
                    url: source.url.clone(),
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: source.body.clone(),
                    network_policy: NetworkPolicy {
                        allowed_targets: vec![NetworkTargetPattern {
                            scheme: Some(NetworkScheme::Https),
                            host_pattern: source.host.clone(),
                            port: None,
                        }],
                        deny_private_ip_ranges: true,
                        max_egress_bytes: None,
                    },
                    credential_injections: Vec::new(),
                    response_body_limit: Some(
                        source.response_body_limit.min(TOKEN_RESPONSE_LIMIT_BYTES),
                    ),
                    save_body_to: None,
                    timeout_ms: Some(u32::try_from(CHANNEL_EGRESS_TIMEOUT_MS).unwrap_or(u32::MAX)),
                },
                credentials,
            })
            .await
            .map_err(|error| match error.reason_code() {
                RuntimeHttpEgressReasonCode::CredentialUnavailable => Failure::ExchangeRejected,
                RuntimeHttpEgressReasonCode::NetworkError
                | RuntimeHttpEgressReasonCode::ResponseError => Failure::ExchangeUnavailable,
                RuntimeHttpEgressReasonCode::PolicyDenied
                | RuntimeHttpEgressReasonCode::RequestDenied
                | RuntimeHttpEgressReasonCode::ResponseBodyLimitExceeded => {
                    Failure::ExchangeMisdeclared
                }
            })?;
        // The body carries the token: scrub it however this function exits.
        let body = Zeroizing::new(response.body);
        // The network layer enforces the limit; this is the defensive twin.
        if body.len() as u64 > TOKEN_RESPONSE_LIMIT_BYTES {
            return Err(Failure::ExchangeMisdeclared);
        }
        match response.status {
            200..=299 => {}
            401 | 403 => return Err(Failure::ExchangeRejected),
            408 | 429 | 500..=599 => return Err(Failure::ExchangeUnavailable),
            _ => return Err(Failure::ExchangeMisdeclared),
        }
        let (material, expires_in) = extract_token(&body, source)?;
        Ok((material, refresh_after(expires_in)))
    }
}

/// Parse the exchange response. The token is moved out of the parsed tree into
/// a scrubbed buffer and then into the secret type without a copy.
fn extract_token(
    body: &[u8],
    source: &ApprovedCredentialSource,
) -> Result<(SecretMaterial, Option<u64>), ChannelEgressCredentialError> {
    use ChannelEgressCredentialError as Failure;
    let mut value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_malformed| Failure::ExchangeUnavailable)?;
    let expires_in = value
        .pointer(&source.expires_in_pointer)
        .and_then(lifetime_seconds);
    let mut token = match value
        .pointer_mut(&source.token_pointer)
        .map(serde_json::Value::take)
    {
        Some(serde_json::Value::String(token)) => Zeroizing::new(token),
        _ => return Err(Failure::ExchangeUnavailable),
    };
    // The value lands in a request header: visible ASCII only, bounded, so a
    // hostile or broken response cannot smuggle CR/LF or oversize a header.
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(Failure::ExchangeUnavailable);
    }
    Ok((SecretString::from(std::mem::take(&mut *token)), expires_in))
}

/// A lifetime in seconds: a JSON number or an all-digit string.
fn lifetime_seconds(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text)
            if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            text.parse().ok()
        }
        _ => None,
    }
}

#[async_trait]
impl ChannelEgressCredentialsPort for TokenExchangeEgressCredentials {
    async fn channel_secret(
        &self,
        extension_id: &str,
        installation_id: &str,
        handle: &SecretHandle,
    ) -> Result<Option<SecretMaterial>, ChannelEgressCredentialError> {
        self.inner
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
        let slot = self.slot_for((
            extension_id.to_string(),
            installation_id.to_string(),
            source.handle.as_str().to_string(),
            source.url.clone(),
        ));
        // Holding the slot lock across the exchange is the single flight: a
        // concurrent caller waits here, then finds the fresh token.
        let mut slot = slot.lock().await;
        if let TokenRefresh::Invalidate { generation } = refresh
            && slot
                .token
                .as_ref()
                .is_some_and(|token| token.generation == generation)
        {
            // Only the token the failing request used is dropped; a token a
            // concurrent caller already replaced is kept.
            slot.token = None;
        }
        if let Some(token) = &slot.token
            && Instant::now() < token.refresh_at
        {
            return Ok(ExchangedToken {
                material: token.material.clone(),
                generation: token.generation,
            });
        }
        slot.token = None;
        let (material, refresh_after) =
            self.exchange(extension_id, installation_id, source).await?;
        slot.next_generation += 1;
        let generation = slot.next_generation;
        slot.token = Some(CachedToken {
            material: material.clone(),
            refresh_at: Instant::now() + refresh_after,
            generation,
        });
        Ok(ExchangedToken {
            material,
            generation,
        })
    }
}

/// Mapping from an exchange failure to the restricted-egress error an adapter
/// sees. Every reason is a static string: no status, body, token, or URL.
pub(super) fn map_exchange_error(
    error: ChannelEgressCredentialError,
    source: &ApprovedCredentialSource,
) -> RestrictedEgressError {
    match error {
        ChannelEgressCredentialError::ExchangeRejected => RestrictedEgressError::AuthRequired {
            required_secrets: source
                .credentials
                .iter()
                .map(|credential| credential.handle.clone())
                .collect(),
            credential_requirements: Vec::new(),
        },
        ChannelEgressCredentialError::ExchangeUnavailable => RestrictedEgressError::Transport {
            reason: "token exchange unavailable".to_string(),
        },
        ChannelEgressCredentialError::ExchangeMisdeclared
        | ChannelEgressCredentialError::TokenSourceUnavailable => {
            RestrictedEgressError::PolicyDenied
        }
        ChannelEgressCredentialError::Unavailable => RestrictedEgressError::Transport {
            reason: ChannelEgressCredentialError::Unavailable.to_string(),
        },
    }
}

#[cfg(test)]
mod tests;
