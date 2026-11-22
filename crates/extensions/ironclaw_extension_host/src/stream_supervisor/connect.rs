//! The connect call: ask the vendor for a connection grant, then build the
//! WebSocket URL the grant describes.
//!
//! The call rides the channel's own manifest-restricted egress, so the client
//! secret reaches the request body only through the declared
//! `body_credentials` injection and never passes through this module. The
//! response's ticket is a secret: it is moved straight into a scrubbed buffer,
//! lives only inside the URL handed to the network connector, and no error,
//! log, or audit event carries it. Only the endpoint's host name is reported.
use std::time::Duration;

use ironclaw_extension_contracts::channel::ChannelStreamDescriptor;
use ironclaw_extension_contracts::tool_adapter::{RestrictedEgress, RestrictedEgressError};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use zeroize::Zeroizing;

use crate::channel_vendor_calls::{render_vendor_call, resolve_vendor_call_target};

/// Query-value encoding: everything but RFC 3986 unreserved characters.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// A connection grant ready to dial.
pub(super) struct ConnectGrant {
    /// Full WebSocket URL; embeds the ticket.
    pub url: Zeroizing<String>,
    /// The endpoint's host name (declared-host checked), safe to report.
    pub host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConnectFailureKind {
    /// Credentials refused or missing. Counts toward "needs administrator".
    Auth,
    /// The vendor rejected or the declaration is wrong in a way a retry will
    /// not fix. Counts toward "needs administrator".
    Rejected,
    /// Network, timeout, 5xx, 429, malformed response: retry with backoff.
    Transient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConnectFailure {
    pub kind: ConnectFailureKind,
    pub reason: &'static str,
}

const fn failure(kind: ConnectFailureKind, reason: &'static str) -> ConnectFailure {
    ConnectFailure { kind, reason }
}

/// Run the connect call and resolve the grant.
pub(super) async fn request_grant(
    descriptor: &ChannelStreamDescriptor,
    resolved: &ironclaw_extension_registry::ResolvedExtensionManifest,
    config: &[(String, String)],
    egress: &dyn RestrictedEgress,
    deadline: Duration,
) -> Result<ConnectGrant, ConnectFailure> {
    let channel = resolved
        .channel
        .as_ref()
        .ok_or(failure(ConnectFailureKind::Rejected, "no_channel"))?;
    let target = resolve_vendor_call_target(&descriptor.connect, channel.egress.as_slice())
        .map_err(|_declaration| {
            failure(ConnectFailureKind::Rejected, "connect_target_undeclared")
        })?;
    let mut request = render_vendor_call(
        &descriptor.connect,
        &target.host,
        target.credential_handle.as_ref(),
        config,
    )
    .map_err(|_render| failure(ConnectFailureKind::Rejected, "connect_request_invalid"))?;
    request.body = Some(with_subscriptions(request.body.take(), descriptor)?);

    let response = match tokio::time::timeout(deadline, egress.send(request)).await {
        Err(_elapsed) => return Err(failure(ConnectFailureKind::Transient, "connect_timeout")),
        Ok(Ok(response)) => response,
        Ok(Err(error)) => return Err(classify_egress_error(&error)),
    };
    // The body holds the ticket: scrub it however this function exits.
    let body = Zeroizing::new(response.body);
    match response.status {
        200..=299 => {}
        401 | 403 => return Err(failure(ConnectFailureKind::Auth, "connect_unauthorized")),
        429 | 500..=599 => {
            return Err(failure(
                ConnectFailureKind::Transient,
                "connect_unavailable",
            ));
        }
        _ => return Err(failure(ConnectFailureKind::Rejected, "connect_rejected")),
    }
    let (endpoint, ticket) = extract_grant(&body, descriptor)?;
    let host = validate_endpoint(&endpoint, descriptor)?;
    let url = build_url(&descriptor.url_template, &endpoint, &ticket);
    Ok(ConnectGrant { url, host })
}

fn classify_egress_error(error: &RestrictedEgressError) -> ConnectFailure {
    match error {
        RestrictedEgressError::AuthRequired { .. } => {
            failure(ConnectFailureKind::Auth, "connect_credentials_missing")
        }
        RestrictedEgressError::UndeclaredHost { .. }
        | RestrictedEgressError::UndeclaredMethod
        | RestrictedEgressError::HostOwnedHeader { .. }
        | RestrictedEgressError::UndeclaredCredential { .. }
        | RestrictedEgressError::PolicyDenied => {
            failure(ConnectFailureKind::Rejected, "connect_policy_denied")
        }
        RestrictedEgressError::ResponseTooLarge => {
            failure(ConnectFailureKind::Rejected, "connect_response_too_large")
        }
        RestrictedEgressError::Transport { .. } => {
            failure(ConnectFailureKind::Transient, "connect_transport")
        }
    }
}

/// Add the declared subscriptions to the connect body (unless the recipe's own
/// body already names `subscriptions`). The body is otherwise exactly what the
/// recipe rendered; secrets are injected later, host-side, by the egress.
fn with_subscriptions(
    body: Option<Vec<u8>>,
    descriptor: &ChannelStreamDescriptor,
) -> Result<Vec<u8>, ConnectFailure> {
    let invalid = || failure(ConnectFailureKind::Rejected, "connect_request_invalid");
    let mut value = match body {
        Some(bytes) => {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_parse| invalid())?
        }
        None => serde_json::Value::Object(serde_json::Map::new()),
    };
    let serde_json::Value::Object(fields) = &mut value else {
        return Err(invalid());
    };
    if !descriptor.subscriptions.is_empty() && !fields.contains_key("subscriptions") {
        fields.insert(
            "subscriptions".to_string(),
            serde_json::Value::Array(
                descriptor
                    .subscriptions
                    .iter()
                    .map(|s| serde_json::json!({ "type": s.kind, "topic": s.topic }))
                    .collect(),
            ),
        );
    }
    serde_json::to_vec(&value).map_err(|_serialize| invalid())
}

fn extract_grant(
    body: &[u8],
    descriptor: &ChannelStreamDescriptor,
) -> Result<(String, Zeroizing<String>), ConnectFailure> {
    let invalid = || failure(ConnectFailureKind::Transient, "connect_response_invalid");
    let mut value: serde_json::Value = serde_json::from_slice(body).map_err(|_parse| invalid())?;
    let endpoint = match value.pointer(&descriptor.response.endpoint) {
        Some(serde_json::Value::String(endpoint)) => endpoint.clone(),
        _ => return Err(invalid()),
    };
    // Move the ticket out of the parsed tree into a scrubbed buffer.
    let ticket = match value
        .pointer_mut(&descriptor.response.ticket)
        .map(serde_json::Value::take)
    {
        Some(serde_json::Value::String(ticket)) if !ticket.is_empty() => Zeroizing::new(ticket),
        _ => return Err(invalid()),
    };
    Ok((endpoint, ticket))
}

/// The endpoint must be a plain `wss` URL whose host is one of the declared
/// hosts, on the default port, with no credentials, query, or fragment (the
/// ticket is appended by the template, nothing may ride along).
fn validate_endpoint(
    endpoint: &str,
    descriptor: &ChannelStreamDescriptor,
) -> Result<String, ConnectFailure> {
    let denied = || failure(ConnectFailureKind::Rejected, "endpoint_host_not_declared");
    let url = url::Url::parse(endpoint).map_err(|_parse| denied())?;
    if url.scheme() != "wss"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|port| port != 443)
    {
        return Err(denied());
    }
    let host = url.host_str().ok_or_else(denied)?.to_ascii_lowercase();
    if descriptor.hosts.contains(&host) {
        Ok(host)
    } else {
        Err(denied())
    }
}

/// `{endpoint}` verbatim, `{ticket}` percent-encoded (the vendor encodes it as
/// a query value).
fn build_url(template: &str, endpoint: &str, ticket: &str) -> Zeroizing<String> {
    // Sized for the worst case (every ticket byte percent-encoded) so the
    // buffer never grows: a reallocation would leave an unscrubbed copy of the
    // ticket behind.
    let capacity = template.len() + endpoint.len() + ticket.len() * 3;
    let mut url = Zeroizing::new(String::with_capacity(capacity));
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        url.push_str(&rest[..open]);
        rest = &rest[open..];
        if let Some(after) = rest.strip_prefix("{endpoint}") {
            url.push_str(endpoint);
            rest = after;
        } else if let Some(after) = rest.strip_prefix("{ticket}") {
            for piece in utf8_percent_encode(ticket, QUERY_VALUE) {
                url.push_str(piece);
            }
            rest = after;
        } else {
            url.push('{');
            rest = &rest[1..];
        }
    }
    url.push_str(rest);
    url
}

#[cfg(test)]
mod tests {
    use super::build_url;

    #[test]
    fn build_url_is_written_once_into_a_preallocated_buffer() {
        // Review #7: growth reallocations would leave unscrubbed copies of the
        // ticket behind, so the buffer is sized up front and never grows.
        let endpoint = "wss://stream.example/connect";
        let ticket = "t/k+n=1 é";
        let url = build_url("{endpoint}?ticket={ticket}", endpoint, ticket);
        assert_eq!(
            url.as_str(),
            "wss://stream.example/connect?ticket=t%2Fk%2Bn%3D1%20%C3%A9"
        );
        assert_eq!(
            url.capacity(),
            "{endpoint}?ticket={ticket}".len() + endpoint.len() + ticket.len() * 3
        );
    }
}
