//! `[channel.egress.credential_source]`: a short-lived token the host
//! exchanges for application credentials and injects into outbound requests.
//!
//! The manifest is the sole authority for every part of the exchange: which
//! declared egress endpoint is called, which secret handles ride its body (via
//! that endpoint's own `body_credentials`), which JSON pointers carry the token
//! and its lifetime in seconds, and which request header receives the token.
//! Adapters opt in per request by naming [`ChannelCredentialSourceDescriptor::handle`]
//! in `RestrictedEgressRequest::credential` and never see token bytes. The
//! handle is a logical name only: it is never an admin-configuration field and
//! never keys a stored secret.
use serde::{Deserialize, Serialize};

use ironclaw_host_api::{action::NetworkMethod, action::NetworkScheme, ids::SecretHandle};

use crate::channel::{
    ChannelDescriptorError, ChannelEgressDescriptor, ChannelVendorCallMethod,
    ChannelVendorCallRecipe, valid_egress_path_constraint,
};

const MAX_POINTER_BYTES: usize = 256;
const MAX_HEADER_NAME_BYTES: usize = 64;
const MAX_HEADER_PREFIX_BYTES: usize = 32;
/// Headers the host owns or that change message framing or connection
/// semantics; a token may not be injected into them. `authorization` is
/// deliberately absent: it is the usual host-owned injection header.
const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "te",
    "trailer",
    "cookie",
];

/// How the host obtains and injects an exchanged token for one egress target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelCredentialSourceDescriptor {
    /// Logical name of the exchanged token. Adapters name it in the request's
    /// `credential`; it is never stored and is not an admin-configuration field.
    pub handle: SecretHandle,
    /// Host of the exchange endpoint. It must equal the host of another
    /// declared `[[channel.egress]]` target that declares the exchange path.
    pub exchange_host: String,
    /// The exchange call. Its `body_credentials` handles are injected by the
    /// exchange target's own `body_credentials` pointers, host-side.
    pub exchange: ChannelVendorCallRecipe,
    /// RFC 6901 pointer to the token in the exchange response.
    pub token_pointer: String,
    /// RFC 6901 pointer to the token lifetime in the exchange response.
    /// The unit is seconds.
    pub expires_in_pointer: String,
    /// Where the host injects the token on this target.
    pub header: ChannelCredentialSourceHeader,
}

/// The request header that receives the exchanged token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelCredentialSourceHeader {
    /// Lowercase header name.
    pub name: String,
    /// Text placed before the token, for example `Bearer `.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

impl ChannelCredentialSourceDescriptor {
    /// Validates the source declared on `all[index]` against its siblings.
    pub(crate) fn validate(
        &self,
        index: usize,
        all: &[ChannelEgressDescriptor],
    ) -> Result<(), ChannelDescriptorError> {
        let target = &all[index];
        let host = || target.host.clone();
        let invalid = |field: &'static str| ChannelDescriptorError::InvalidCredentialSource {
            host: host(),
            field,
        };
        if target.credential_handle.is_some()
            || target.injection.is_some()
            || !target.body_credentials.is_empty()
        {
            return Err(
                ChannelDescriptorError::CredentialSourceWithStaticCredential { host: host() },
            );
        }
        let pointer_ok = |value: &str| {
            !value.is_empty()
                && value.len() <= MAX_POINTER_BYTES
                && value.starts_with('/')
                && !value.chars().any(char::is_control)
                && valid_pointer_escapes(value)
        };
        if !pointer_ok(&self.token_pointer) {
            return Err(invalid("token_pointer"));
        }
        if !pointer_ok(&self.expires_in_pointer) || self.expires_in_pointer == self.token_pointer {
            return Err(invalid("expires_in_pointer"));
        }
        // App credentials ride a JSON body, so only a POST exchange is allowed.
        if self.exchange.method != ChannelVendorCallMethod::Post {
            return Err(invalid("exchange.method"));
        }
        let path = self.exchange.path.as_str();
        if !path.starts_with('/')
            || path.contains(['?', '#'])
            || !valid_egress_path_constraint(path, None)
        {
            return Err(invalid("exchange.path"));
        }
        match &self.exchange.body {
            None => {}
            Some(serde_json::Value::Object(_))
                if !json_has_placeholder(self.exchange.body.as_ref()) => {}
            Some(_) => return Err(invalid("exchange.body")),
        }
        let name = self.header.name.as_str();
        if name.is_empty()
            || name.len() > MAX_HEADER_NAME_BYTES
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || FORBIDDEN_HEADERS.contains(&name)
        {
            return Err(invalid("header.name"));
        }
        if let Some(prefix) = &self.header.prefix
            && (prefix.len() > MAX_HEADER_PREFIX_BYTES || prefix.chars().any(char::is_control))
        {
            return Err(invalid("header.prefix"));
        }
        // The token handle names no other declared secret.
        for (other_index, other) in all.iter().enumerate() {
            let static_handles = other
                .credential_handle
                .iter()
                .chain(other.body_credentials.iter().map(|b| &b.handle));
            let other_source = other
                .credential_source
                .as_ref()
                .filter(|_| other_index != index)
                .map(|source| &source.handle);
            if static_handles
                .chain(other_source)
                .any(|h| *h == self.handle)
            {
                return Err(invalid("handle"));
            }
        }
        // The exchange endpoint is exactly one other, https, declared target.
        let method = NetworkMethod::Post;
        let mut matches = all.iter().enumerate().filter(|(other_index, other)| {
            *other_index != index
                && other.host.eq_ignore_ascii_case(&self.exchange_host)
                && other.methods.contains(&method)
                && (other.paths.iter().any(|p| p == path)
                    || other
                        .path_prefixes
                        .iter()
                        .any(|p| path.starts_with(p.as_str())))
        });
        let (Some((_, exchange_target)), None) = (matches.next(), matches.next()) else {
            return Err(invalid("exchange_host"));
        };
        if exchange_target.scheme != NetworkScheme::Https {
            return Err(invalid("exchange_host"));
        }
        if exchange_target.credential_source.is_some() {
            return Err(invalid("exchange_host"));
        }
        // The exchange carries app credentials injected host-side by the
        // exchange target's declared pointers; the token never names itself.
        let handles = &self.exchange.body_credentials;
        if handles.is_empty()
            || handles.iter().enumerate().any(|(i, handle)| {
                *handle == self.handle
                    || handles[..i].contains(handle)
                    || !exchange_target
                        .body_credentials
                        .iter()
                        .any(|declared| declared.handle == *handle)
            })
        {
            return Err(invalid("exchange.body_credentials"));
        }
        Ok(())
    }
}

/// RFC 6901: `~` must be followed by `0` or `1`.
fn valid_pointer_escapes(pointer: &str) -> bool {
    let mut chars = pointer.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

/// Whether any string value in the template carries a `{` or `}`. The exchange
/// runs in the transport, which has no configuration to substitute from.
fn json_has_placeholder(value: Option<&serde_json::Value>) -> bool {
    match value {
        None => false,
        Some(serde_json::Value::String(text)) => text.contains(['{', '}']),
        Some(serde_json::Value::Array(items)) => {
            items.iter().any(|v| json_has_placeholder(Some(v)))
        }
        Some(serde_json::Value::Object(map)) => map.values().any(|v| json_has_placeholder(Some(v))),
        Some(_) => false,
    }
}
