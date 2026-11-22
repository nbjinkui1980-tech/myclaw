//! Transport-neutral generic ingress router.
//!
//! See the module docs in [`super`] for the pinned per-request order. The
//! router owns semantics and security; the extension contributes exactly one
//! pure call (`ChannelAdapter::inbound`). Ordinary messages reach the durable
//! admission commit before 2xx. Provider-batch fragments reach host-private
//! durable staging before 2xx, then one leased background worker admits the
//! merged message after the provider-selected quiet window (checklist ING-8).

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ironclaw_extension_contracts::channel::{ChannelIngressDescriptor, ChannelIngressMethod};
use ironclaw_extension_contracts::channel_adapter::{
    ChannelIngress, NormalizedInboundMessage, VerifiedInbound,
};
use ironclaw_extension_contracts::tool_adapter::RestrictedEgress;
use ironclaw_extension_registry::ResolvedExtensionManifest;
use ironclaw_host_api::ids::SecretHandle;

use crate::active::ActiveExtension;
use crate::deployment_channels::{DeploymentChannelBinding, DeploymentChannelRegistry};
use crate::egress::ChannelEgressTransport;
use crate::inbound_batches::InboundBatchStore;
use crate::lifecycle::SnapshotWatch;

use super::admission::{
    AdmissionDisposition, InboundBatchProcessor, StreamAdmission, channel_restricted_egress,
    dispose_outcome, receive_verified, resolved_binding_fingerprint,
};
use super::verifier::{IngressHeaders, VerificationCandidate, verify_recipe};

/// The canonical mounted path for one extension channel's ingress route.
pub fn canonical_ingress_path(extension_id: &str, route_suffix: &str) -> String {
    format!("/webhooks/extensions/{extension_id}/{route_suffix}")
}

/// A failed ingress port call. Ports fail closed: the router maps this to a
/// retryable 503 (never a 2xx).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ingress port unavailable: {reason}")]
pub struct IngressPortError {
    pub reason: String,
}

/// Resolves the verification-secret candidates for one extension route.
/// Implemented by composition over the host secret/config stores — secrets
/// stay host-side; the router hands them only to the constant-time verifier.
#[async_trait]
pub trait IngressSecretsPort: Send + Sync {
    /// Candidate installations (id + secret bytes) for this route. `handle`
    /// is `None` for `kind = "none"` recipes, where only the installation
    /// identity is needed and returned secrets must be empty.
    async fn verification_candidates(
        &self,
        extension_id: &str,
        installation_id: &str,
        handle: Option<&SecretHandle>,
    ) -> Result<Vec<VerificationCandidate>, IngressPortError>;
}

/// Resolves manifest-declared non-secret configuration for the installation
/// selected by ingress verification. Implementations must not return secret
/// values or handles.
#[async_trait]
pub trait IngressConfigurationPort: Send + Sync {
    async fn non_secret_config(
        &self,
        extension_id: &str,
        installation_id: &str,
    ) -> Result<Vec<(String, String)>, IngressPortError>;
}

/// One verified, normalized inbound message ready for durable admission.
pub struct InboundAdmission {
    pub extension_id: String,
    pub installation_id: String,
    pub message: NormalizedInboundMessage,
}

/// The durable admission outcome. Both variants mean the event is durably
/// accounted for — the router may 2xx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundAdmissionAck {
    Accepted,
    /// The `(installation, event_id)` dedupe key was already settled.
    Duplicate,
}

/// A failed admission. `retryable` selects 503 (vendor should redeliver)
/// versus an acknowledged discard (the same message re-fails on every
/// redelivery, so the router 2xx-acks it away and warn-logs the drop).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("inbound admission failed: {reason}")]
pub struct InboundSinkError {
    pub retryable: bool,
    pub reason: String,
}

/// The durable dedupe + admission commit seam (one transaction keyed
/// `(installation, event_id)`), implemented by composition over the existing
/// product workflow (idempotency ledger → identity/conversation binding →
/// turn submission).
#[async_trait]
pub trait InboundSink: Send + Sync {
    async fn admit(
        &self,
        admission: InboundAdmission,
    ) -> Result<InboundAdmissionAck, InboundSinkError>;
}

/// Host-side storage key for an inbound message's opaque `reply_context`:
/// the conversation source binding it will be handed back for at delivery
/// time (checklist ING-11).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReplyContextKey {
    pub extension_id: String,
    pub installation_id: String,
    /// The conversation fingerprint
    /// ([`ironclaw_extension_contracts::external::ExternalConversationRef::conversation_fingerprint`]).
    pub conversation: String,
}

/// Host-side `reply_context` storage. Stored before admission commits;
/// the delivery coordinator (P5) reads it back for source-route replies.
#[async_trait]
pub trait ReplyContextStore: Send + Sync {
    async fn put(&self, key: ReplyContextKey, context: Vec<u8>) -> Result<(), IngressPortError>;
    async fn get(&self, key: &ReplyContextKey) -> Result<Option<Vec<u8>>, IngressPortError>;
}

/// Per-installation token-bucket rate limit (defaults match the previous
/// host-served channel ingress: 120 requests / 60 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressRateLimitConfig {
    pub max_requests: u32,
    pub window: Duration,
}

impl Default for IngressRateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 120,
            window: Duration::from_secs(60),
        }
    }
}

/// Router-wide configuration.
#[derive(Debug, Clone, Copy)]
pub struct IngressRouterConfig {
    pub rate_limit: IngressRateLimitConfig,
    /// Bounded budget for verification + adapter + admission per request.
    pub request_deadline: Duration,
}

impl Default for IngressRouterConfig {
    fn default() -> Self {
        Self {
            rate_limit: IngressRateLimitConfig::default(),
            request_deadline: Duration::from_secs(20),
        }
    }
}

/// One inbound HTTP request, transport-neutral. Composition extracts the two
/// path segments from the mounted route pattern.
pub struct IngressRequest {
    /// HTTP method token (e.g. `POST`), matched case-insensitively.
    pub method: String,
    pub extension_id: String,
    pub route_suffix: String,
    /// Raw header entries in wire order (duplicates preserved — duplicate
    /// verification headers must be observable to fail closed).
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// The router's response, mapped 1:1 onto the HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Body marker for [`IngressResponse::acknowledged_discarded`]. The batch
/// processor keys its terminal-state decision on it, and operators reading
/// HTTP captures can tell a discard from an ordinary ack.
const ACKNOWLEDGED_DISCARDED_BODY: &[u8] = br#"{"status":"acknowledged_discarded"}"#;

impl IngressResponse {
    fn error(status: u16, category: &str) -> Self {
        Self {
            status,
            content_type: Some("application/json".to_string()),
            body: format!("{{\"error\":\"{category}\"}}").into_bytes(),
        }
    }

    fn ok() -> Self {
        Self {
            status: 200,
            content_type: Some("text/plain".to_string()),
            body: b"ok".to_vec(),
        }
    }

    /// 2xx acknowledgment for a verified update the host consciously drops.
    /// Deterministic failures replay identically on redelivery, and vendors
    /// with ordered webhook queues redeliver any non-2xx update and hold
    /// every later update in the conversation behind it — one unusable
    /// update bricked a whole chat. Every discard is logged at warn by its
    /// call site; nothing is admitted.
    fn acknowledged_discarded() -> Self {
        Self {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: ACKNOWLEDGED_DISCARDED_BODY.to_vec(),
        }
    }
}

/// Injected router dependencies (composition supplies concrete ports).
#[derive(Clone)]
pub struct ExtensionIngressRouterDeps {
    pub secrets: Arc<dyn IngressSecretsPort>,
    pub configuration: Arc<dyn IngressConfigurationPort>,
    pub sink: Arc<dyn InboundSink>,
    pub reply_context: Arc<dyn ReplyContextStore>,
    /// Host-private durable staging for provider-level batches whose
    /// fragments arrive as separate webhook requests.
    pub inbound_batches: Arc<dyn InboundBatchStore>,
    /// Host transport used only to construct per-request manifest-restricted
    /// egress from the already pinned ingress binding.
    // arch-exempt: optional_arc, minimal/test host-runtime graphs intentionally
    // omit HTTP egress; absence preserves the explicit fail-closed 503 path for
    // attachment-bearing messages, plan #4539
    pub channel_egress_transport: Option<Arc<dyn ChannelEgressTransport>>,
}

/// Map the shared pipeline's transport-neutral result onto the HTTP response.
fn disposition_response(disposition: AdmissionDisposition) -> IngressResponse {
    match disposition {
        AdmissionDisposition::Admitted
        | AdmissionDisposition::Ignored
        | AdmissionDisposition::BatchStaged => IngressResponse::ok(),
        AdmissionDisposition::Respond(response) => IngressResponse {
            status: response.status,
            content_type: response.content_type,
            body: response.body,
        },
        AdmissionDisposition::Transient => IngressResponse::error(503, "temporarily_unavailable"),
        AdmissionDisposition::DeterministicDiscard => IngressResponse::acknowledged_discarded(),
        AdmissionDisposition::HostBoundViolation => IngressResponse::error(500, "adapter"),
    }
}

/// The generic ingress router. One instance serves every active extension's
/// channel ingress; resolution is per request through the snapshot watch.
pub struct ExtensionIngressRouter {
    watch: SnapshotWatch,
    deployment_channels: Arc<DeploymentChannelRegistry>,
    deps: ExtensionIngressRouterDeps,
    config: IngressRouterConfig,
    rate: RateLimiter,
    batch_processor: InboundBatchProcessor,
}

impl ExtensionIngressRouter {
    pub fn new(
        watch: SnapshotWatch,
        deps: ExtensionIngressRouterDeps,
        config: IngressRouterConfig,
    ) -> Self {
        let deployment_channels = Arc::new(DeploymentChannelRegistry::default());
        let batch_processor = InboundBatchProcessor {
            watch: watch.clone(),
            deployment_channels: Arc::clone(&deployment_channels),
            deps: deps.clone(),
            recovery_started: Arc::new(AtomicBool::new(false)),
            admission_deadline: config.request_deadline,
        };
        Self {
            watch,
            deployment_channels,
            deps,
            rate: RateLimiter::new(config.rate_limit),
            config,
            batch_processor,
        }
    }

    /// Resolve manifest-declared deployment ingress independently of the
    /// user-installation active snapshot.
    pub fn with_deployment_channels(
        mut self,
        deployment_channels: Arc<DeploymentChannelRegistry>,
    ) -> Self {
        self.deployment_channels = Arc::clone(&deployment_channels);
        self.batch_processor.deployment_channels = deployment_channels;
        self
    }

    /// Start the durable recovery sweep after the final deployment bindings
    /// have been attached. The sweep immediately reclaims due work and then
    /// periodically retries unavailable bindings or expired leases.
    pub fn start_pending_batch_recovery(&self) {
        self.batch_processor.start_recovery_sweep();
    }

    /// Handle one request following the pinned order. Never panics; never
    /// returns 2xx before the outcome's durable boundary (ordinary admission
    /// or provider-batch fragment staging).
    pub async fn handle(&self, request: IngressRequest) -> IngressResponse {
        // 1. Match deployment ingress first. User activation remains a
        // compatibility source for extensions not linked into the deployment
        // registry; it is not required for operator-configured channels.
        let binding = self
            .deployment_channels
            .resolve_channel_ingress(&request.extension_id, &request.route_suffix)
            .map(ResolvedIngressBinding::Deployment)
            .or_else(|| {
                self.watch
                    .current()
                    .resolve_channel_ingress(&request.extension_id, &request.route_suffix)
                    .map(ResolvedIngressBinding::Active)
            });
        let Some(binding) = binding else {
            return IngressResponse::error(404, "unknown_route");
        };
        let Some(ingress) = binding
            .resolved()
            .channel
            .as_ref()
            .and_then(|channel| channel.ingress.as_ref())
        else {
            return IngressResponse::error(404, "unknown_route");
        };

        // 2. Method / body-limit — before any verification or adapter work.
        //    The installation-scoped limiter runs only after verification;
        //    otherwise unauthenticated traffic could drain a real vendor's
        //    shared bucket. The public transport keeps its own pre-auth cap.
        if !method_allowed(&request.method, ingress) {
            return IngressResponse::error(405, "method_not_allowed");
        }
        if request.body.len() as u64 > ingress.body_limit_bytes {
            return IngressResponse::error(413, "payload_too_large");
        }
        // 3. Deadline around verification + adapter + durable admission.
        let deadline = self.config.request_deadline;
        match tokio::time::timeout(
            deadline,
            self.verify_and_dispatch(&request, &binding, ingress),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                tracing::debug!(
                    extension_id = %request.extension_id,
                    "extension ingress request exceeded its bounded deadline"
                );
                IngressResponse::error(503, "temporarily_unavailable")
            }
        }
    }

    async fn verify_and_dispatch(
        &self,
        request: &IngressRequest,
        binding: &ResolvedIngressBinding,
        ingress: &ChannelIngressDescriptor,
    ) -> IngressResponse {
        // 4. Verification recipe execution — host-side, before the adapter.
        // Only webhook ingress mounts a route, so any other transport reaching
        // here is a routing bug: fail closed as an unknown route.
        let Some(verification) = ingress.webhook_verification() else {
            return IngressResponse::error(404, "unknown_route");
        };
        let candidates = match self
            .deps
            .secrets
            .verification_candidates(
                binding.extension_id(),
                binding.installation_hint(),
                verification.secret_handle(),
            )
            .await
        {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::debug!(
                    extension_id = %binding.extension_id(),
                    error = %error,
                    "extension ingress verification secrets unavailable"
                );
                return IngressResponse::error(503, "temporarily_unavailable");
            }
        };
        let now_unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        let verified = match verify_recipe(
            verification,
            &IngressHeaders::new(&request.headers),
            &request.body,
            now_unix_seconds,
            &candidates,
        ) {
            Ok(verified) => verified,
            Err(failure) => {
                tracing::debug!(
                    extension_id = %binding.extension_id(),
                    failure = %failure,
                    "extension ingress verification rejected"
                );
                return IngressResponse::error(401, "authentication");
            }
        };
        drop(candidates); // secrets leave scope before any adapter work

        // Charge only authenticated vendor traffic, keyed by the verified
        // installation rather than the public extension route. A forged
        // request may spend verification work, but cannot deny the genuine
        // installation its bounded admission capacity.
        let rate_key = format!("{}:{}", binding.extension_id(), verified.installation_id);
        if !self.rate.try_admit(&rate_key) {
            return IngressResponse::error(429, "capacity");
        }

        // 5. Resolve only manifest-declared non-secret configuration for the
        //    installation selected by successful verification.
        let non_secret_config = match self
            .deps
            .configuration
            .non_secret_config(binding.extension_id(), &verified.installation_id)
            .await
        {
            Ok(config) => config,
            Err(error) => {
                tracing::debug!(
                    extension_id = %binding.extension_id(),
                    error = %error,
                    "extension ingress non-secret configuration unavailable"
                );
                return IngressResponse::error(503, "temporarily_unavailable");
            }
        };

        // 6. adapter.inbound — pure, panic-isolated; verification headers are
        //    consumed by the host and never forwarded.
        let Some(channel) = binding.adapter() else {
            return IngressResponse::error(404, "unknown_route");
        };
        let forwarded_headers: Vec<(String, String)> = request
            .headers
            .iter()
            .filter(|(name, _)| {
                !verified
                    .consumed_headers
                    .iter()
                    .any(|consumed| consumed.eq_ignore_ascii_case(name))
            })
            .map(|(name, value)| (name.clone(), String::from_utf8_lossy(value).into_owned()))
            .collect();
        let channel_egress = self.channel_egress(binding, &verified.installation_id);
        let can_reply_in_threads = binding
            .resolved()
            .channel
            .as_ref()
            .is_some_and(|channel| channel.presentation.can_reply_in_threads);
        let inbound = VerifiedInbound {
            extension_id: binding.extension_id(),
            installation_id: &verified.installation_id,
            config: &non_secret_config,
            body: &request.body,
            headers: &forwarded_headers,
            can_reply_in_threads,
        };
        let outcome =
            match receive_verified(channel.as_ref(), inbound, channel_egress.as_ref()).await {
                Ok(outcome) => outcome,
                Err(disposition) => return disposition_response(disposition),
            };

        // 7. Outcome handling. 2xx only after the outcome's durable boundary:
        // admission for ordinary messages, staging for provider batches.
        disposition_response(
            dispose_outcome(
                &self.batch_processor,
                binding.extension_id(),
                &verified.installation_id,
                outcome,
                || binding.fingerprint(),
            )
            .await,
        )
    }

    fn channel_egress(
        &self,
        binding: &ResolvedIngressBinding,
        installation_id: &str,
    ) -> Arc<dyn RestrictedEgress> {
        channel_restricted_egress(
            self.deps.channel_egress_transport.as_ref(),
            binding.resolved(),
            binding.extension_id(),
            installation_id,
        )
    }
    /// The stream supervisor's door into this router's shared admission
    /// pipeline (same dedupe, `reply_context`, batch staging, and error
    /// classification as webhook requests).
    pub fn stream_admission(&self) -> StreamAdmission {
        StreamAdmission {
            processor: self.batch_processor.clone(),
        }
    }
}
enum ResolvedIngressBinding {
    Deployment(Arc<DeploymentChannelBinding>),
    Active(Arc<ActiveExtension>),
}

impl ResolvedIngressBinding {
    fn extension_id(&self) -> &str {
        match self {
            Self::Deployment(binding) => &binding.extension_id,
            Self::Active(active) => &active.extension_id,
        }
    }

    fn installation_hint(&self) -> &str {
        match self {
            // Deployment ingress has no user installation. The secrets port
            // returns the authoritative installation identity with the
            // successful verification candidate.
            Self::Deployment(binding) => &binding.extension_id,
            Self::Active(active) => &active.installation_id,
        }
    }

    fn resolved(&self) -> &ResolvedExtensionManifest {
        match self {
            Self::Deployment(binding) => binding.resolved.as_ref(),
            Self::Active(active) => active.resolved.as_ref(),
        }
    }

    fn adapter(&self) -> Option<Arc<dyn ChannelIngress>> {
        match self {
            Self::Deployment(binding) => binding.surfaces.ingress.clone(),
            Self::Active(active) => active.channel.ingress.clone(),
        }
    }

    fn fingerprint(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Deployment(binding) => {
                resolved_binding_fingerprint("deployment", binding.resolved.as_ref())
            }
            Self::Active(active) => {
                resolved_binding_fingerprint("active", active.resolved.as_ref())
            }
        }
    }
}

fn method_allowed(method: &str, ingress: &ChannelIngressDescriptor) -> bool {
    match ingress.method {
        ChannelIngressMethod::Post => method.eq_ignore_ascii_case("POST"),
    }
}

/// Token-bucket rate limiter keyed by verified extension installation.
struct RateLimiter {
    config: IngressRateLimitConfig,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last_refilled_at: Instant,
}

impl RateLimiter {
    fn new(config: IngressRateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn try_admit(&self, key: &str) -> bool {
        let now = Instant::now();
        let capacity = f64::from(self.config.max_requests.max(1));
        let mut buckets = match self.buckets.lock() {
            Ok(buckets) => buckets,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Prune buckets idle for two windows to bound memory.
        let ttl = self.config.window.saturating_mul(2);
        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refilled_at) < ttl || bucket.tokens < capacity
        });
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: capacity,
            last_refilled_at: now,
        });
        let elapsed = now.duration_since(bucket.last_refilled_at);
        if !elapsed.is_zero() {
            let refill_ratio = if self.config.window.is_zero() {
                1.0
            } else {
                elapsed.as_secs_f64() / self.config.window.as_secs_f64()
            };
            bucket.tokens = capacity.min(bucket.tokens + refill_ratio * capacity);
            bucket.last_refilled_at = now;
        }
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}
