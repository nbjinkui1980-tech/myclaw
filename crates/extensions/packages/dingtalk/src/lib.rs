//! DingTalk channel extension for Reborn (enterprise-internal robot, Stream mode).
//!
//! The DingTalk side of the Reborn channel contracts defined in
//! `ironclaw_extension_contracts`. The host owns the WebSocket connection
//! (`[channel.ingress.stream]`); this package is a pure protocol translator:
//!
//! * [`stream`] — frame control: which frames get which ACK, `disconnect`
//!   means reconnect, a bot callback's `data` is handed on for `receive`.
//! * [`payload`] — callback parsing and the stateless organisation rule.
//! * [`channel`] — the `ChannelIngress` and `ChannelDelivery` implementations.
//! * [`send`] / [`render`] — the one OpenAPI send path (`oToMessages/batchSend`,
//!   `groupMessages/send`) with the host-exchanged access token.
//!
//! No I/O, no secrets, no raw credential bytes live here.
#![forbid(unsafe_code)]
mod channel;
mod payload;
mod preference_targets;
mod render;
mod reply;
mod reply_context;
mod send;
mod stream;
/// The package manifest, embedded crate-locally so the binary can put the
/// package in the first-party catalog (the same shape as the web-app package;
/// see `crates/app/ironclaw_cli/src/first_party/bundles.rs`).
pub const MANIFEST: &str = include_str!("../manifest.toml");

pub use channel::{DingTalkChannel, DingTalkChannelAdapter, dingtalk_channel};
pub use preference_targets::DingTalkPreferenceTargetCodec;
pub use stream::DingTalkStreamControl;
