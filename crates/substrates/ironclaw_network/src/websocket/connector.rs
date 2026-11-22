use async_trait::async_trait;
use ironclaw_host_api::action::{NetworkMethod, NetworkPolicy, NetworkScheme};
use zeroize::Zeroizing;

use super::{
    connection::WebSocketConnection,
    error::WebSocketError,
    types::{WebSocketConnectRequest, WebSocketTransportRequest},
    upgrade::validate_query,
};
use crate::{
    error::NetworkHttpError,
    policy::StaticNetworkPolicyEnforcer,
    resolver::{NetworkResolver, SystemNetworkResolver, resolve_public_ips},
    types::NetworkRequest,
    url_target::websocket_endpoint,
};

/// Fixed allowance for the upgrade request line and headers when a policy
/// carries an egress-byte cap.
const HANDSHAKE_OVERHEAD_BYTES: u64 = 512;
const WSS_DEFAULT_PORT: u16 = 443;

/// Port other crates hold to open policy-checked outbound WebSockets.
#[async_trait]
pub trait WebSocketConnector: Send + Sync {
    async fn connect(
        &self,
        request: WebSocketConnectRequest,
    ) -> Result<WebSocketConnection, WebSocketError>;
}

/// Dials a connection after policy, DNS, and private-address checks passed.
#[async_trait]
pub trait WebSocketTransport: Send + Sync {
    async fn connect(
        &self,
        request: WebSocketTransportRequest,
    ) -> Result<WebSocketConnection, WebSocketError>;
}

/// Policy front door for outbound WebSockets: `wss` only, exact allow-listed
/// host, port 443 unless the pattern names one, private/reserved address
/// denial, then the transport dials the vetted addresses.
#[derive(Debug, Clone)]
pub struct PolicyWebSocketConnector<T, R = SystemNetworkResolver> {
    transport: T,
    resolver: R,
}

impl<T> PolicyWebSocketConnector<T, SystemNetworkResolver> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            resolver: SystemNetworkResolver,
        }
    }
}

impl<T, R> PolicyWebSocketConnector<T, R> {
    pub fn new_with_resolver(transport: T, resolver: R) -> Self {
        Self {
            transport,
            resolver,
        }
    }
}

#[async_trait]
impl<T, R> WebSocketConnector for PolicyWebSocketConnector<T, R>
where
    T: WebSocketTransport + Send + Sync,
    R: NetworkResolver + Clone + Send + Sync + 'static,
{
    async fn connect(
        &self,
        mut request: WebSocketConnectRequest,
    ) -> Result<WebSocketConnection, WebSocketError> {
        request.limits.validate()?;
        let url = Zeroizing::new(std::mem::take(&mut request.url));
        // Policy and DNS only ever see the endpoint: everything before the
        // first `?`. The ticket-bearing query stays in the scrubbed buffer
        // until the handshake boundary.
        let (endpoint_text, query) = split_endpoint_and_query(&url)?;
        let endpoint =
            websocket_endpoint(endpoint_text).map_err(|error| WebSocketError::InvalidUrl {
                reason: error.to_string(),
            })?;
        if let Some(query) = query {
            validate_query(query)?;
        }
        let target = endpoint.target.clone();
        let policy = websocket_policy(&request.policy);
        let estimated_bytes = u64::try_from(url.len())
            .unwrap_or(u64::MAX)
            .saturating_add(HANDSHAKE_OVERHEAD_BYTES);
        StaticNetworkPolicyEnforcer::new(policy.clone())
            .authorize_blocking(NetworkRequest {
                scope: request.scope.clone(),
                target: target.clone(),
                method: NetworkMethod::Get,
                estimated_bytes: Some(estimated_bytes),
            })
            .map_err(|error| WebSocketError::PolicyDenied {
                reason: error.to_string(),
            })?;

        let resolver = self.resolver.clone();
        let resolve_policy = policy.clone();
        let resolved_ips = tokio::task::spawn_blocking(move || {
            resolve_public_ips(&target, &resolve_policy, &resolver, estimated_bytes)
        })
        .await
        .map_err(|error| WebSocketError::Dns {
            reason: format!("resolver worker failed: {error}"),
        })?
        .map_err(resolution_error)?;

        tracing::debug!(target: "ironclaw_network::websocket", "websocket connect authorized");
        self.transport
            .connect(WebSocketTransportRequest {
                host: endpoint.host,
                port: endpoint.port,
                path: endpoint.path,
                query: query.map(str::to_string),
                resolved_ips,
                deny_private_ip_ranges: policy.deny_private_ip_ranges,
                limits: request.limits,
            })
            .await
    }
}

/// Splits `url` at the first `?` into the ticket-free endpoint and the query.
/// A fragment never belongs in an upgrade request, so `#` anywhere is refused
/// here rather than silently dropped. The error text never repeats the input.
fn split_endpoint_and_query(url: &str) -> Result<(&str, Option<&str>), WebSocketError> {
    if url.contains('#') {
        return Err(WebSocketError::InvalidUrl {
            reason: "websocket URL must not contain a fragment".to_string(),
        });
    }
    Ok(match url.split_once('?') {
        Some((endpoint, query)) => (endpoint, Some(query)),
        None => (url, None),
    })
}

fn resolution_error(error: NetworkHttpError) -> WebSocketError {
    match error {
        NetworkHttpError::PolicyDenied { reason, .. } => WebSocketError::PolicyDenied { reason },
        other => WebSocketError::Dns {
            reason: other.to_string(),
        },
    }
}

/// Narrows a caller policy to what an outbound WebSocket may use: only
/// patterns that name the `wss` scheme and an exact host. Wildcard hosts and
/// scheme-agnostic patterns (which would also authorize HTTP targets) never
/// authorize a WebSocket. A pattern without a port means 443.
fn websocket_policy(policy: &NetworkPolicy) -> NetworkPolicy {
    NetworkPolicy {
        allowed_targets: policy
            .allowed_targets
            .iter()
            .filter(|pattern| {
                pattern.scheme == Some(NetworkScheme::Wss) && !pattern.host_pattern.contains('*')
            })
            .map(|pattern| {
                let mut pattern = pattern.clone();
                pattern.port = Some(pattern.port.unwrap_or(WSS_DEFAULT_PORT));
                pattern
            })
            .collect(),
        deny_private_ip_ranges: policy.deny_private_ip_ranges,
        max_egress_bytes: policy.max_egress_bytes,
    }
}
