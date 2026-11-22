//! The DingTalk channel adapter: `ChannelIngress` for host-delivered stream
//! callbacks.
//!
//! The host owns the connection and has already authenticated it (the sealed
//! stream evidence); this adapter only translates a callback's `data`. It
//! reads no secret and does no I/O.
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelDelivery, ChannelError, ChannelIngress, ChannelSurfaces, DeliveryReport, InboundOutcome,
    OutboundEnvelope, VerifiedInbound,
};
use ironclaw_extension_contracts::preference_target::PreferenceTargetCodec;
use ironclaw_extension_contracts::tool_adapter::RestrictedEgress;

use crate::payload::{CallbackOutcome, normalize_callback};
use crate::preference_targets::DingTalkPreferenceTargetCodec;
use crate::stream::DingTalkStreamControl;

/// The declared OpenAPI host every send goes to.
pub(crate) const DINGTALK_API_HOST: &str = "api.dingtalk.com";
/// Logical handle of the access token the host exchanges for the app
/// credentials (`[channel.egress.credential_source]`). The adapter names it;
/// it never sees token bytes.
pub(crate) const DINGTALK_ACCESS_TOKEN_HANDLE: &str = "dingtalk_access_token";

/// Installations whose robot-code fingerprint is tracked. A bound keeps a
/// hostile installation count from growing the map.
const MAX_TRACKED_INSTALLATIONS: usize = 64;

/// The DingTalk channel adapter.
///
/// `robot_codes` holds a non-cryptographic fingerprint of the last `robotCode`
/// seen per installation, only to log whether it is new, unchanged or changed (ADR §8 item 8b: the
/// equality with `clientId` is verified in Task 20). The value itself is never
/// stored or logged.
#[derive(Debug, Default)]
pub struct DingTalkChannelAdapter {
    robot_codes: Mutex<HashMap<String, u64>>,
    /// Set once the tracking cap was hit, so the saturation is logged once.
    saturation_logged: AtomicBool,
}

impl DingTalkChannelAdapter {
    fn observe_robot_code(&self, installation_id: &str, robot_code: Option<&str>) {
        let Some(code) = robot_code else {
            tracing::debug!(
                robot_code_present = false,
                "dingtalk robot code observation"
            );
            return;
        };
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        code.hash(&mut hasher);
        let fingerprint = hasher.finish();
        let mut seen = self
            .robot_codes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let observation = match seen.get(installation_id) {
            Some(previous) if *previous == fingerprint => RobotCodeObservation::Unchanged,
            Some(_) => RobotCodeObservation::Changed,
            None if seen.len() >= MAX_TRACKED_INSTALLATIONS => {
                // Silence would be ambiguous: say once that tracking is full.
                if !self.saturation_logged.swap(true, Ordering::Relaxed) {
                    tracing::debug!(
                        tracked = MAX_TRACKED_INSTALLATIONS,
                        "dingtalk robot code tracking is full; further installations are not observed"
                    );
                }
                return;
            }
            None => RobotCodeObservation::FirstSeen,
        };
        seen.insert(installation_id.to_string(), fingerprint);
        tracing::debug!(
            robot_code_present = true,
            observation = observation.label(),
            "dingtalk robot code observation"
        );
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RobotCodeObservation {
    FirstSeen,
    Unchanged,
    Changed,
}
impl RobotCodeObservation {
    fn label(self) -> &'static str {
        match self {
            Self::FirstSeen => "first_seen",
            Self::Unchanged => "unchanged",
            Self::Changed => "changed",
        }
    }
}
/// Everything the host binds for DingTalk: the four channel halves and the
/// codec explicit pushes decode their stored target through.
pub struct DingTalkChannel {
    pub surfaces: ChannelSurfaces,
    pub preference_target_codec: Arc<dyn PreferenceTargetCodec>,
}

/// The one assembly of the DingTalk channel (ingress, reply, delivery and
/// stream frame control on one adapter, plus the preference-target codec).
/// The binary and the integration harness both call it, so neither can drift
/// from the other by hand-assembling a half.
pub fn dingtalk_channel() -> DingTalkChannel {
    let adapter = Arc::new(DingTalkChannelAdapter::default());
    DingTalkChannel {
        surfaces: ChannelSurfaces::default()
            .with_ingress(adapter.clone())
            .with_reply(adapter.clone())
            .with_delivery(adapter)
            .with_stream_control(Arc::new(DingTalkStreamControl)),
        preference_target_codec: Arc::new(DingTalkPreferenceTargetCodec),
    }
}

#[async_trait]
impl ChannelIngress for DingTalkChannelAdapter {
    async fn receive(
        &self,
        request: VerifiedInbound<'_>,
        _egress: &dyn RestrictedEgress,
    ) -> Result<InboundOutcome, ChannelError> {
        match normalize_callback(request.body)? {
            CallbackOutcome::Admitted(admitted) => {
                self.observe_robot_code(request.installation_id, admitted.robot_code.as_deref());
                Ok(InboundOutcome::Messages(vec![admitted.message]))
            }
            CallbackOutcome::Ignored(reason) => {
                // `InboundOutcome::Ignore` carries no reason, so the fixed
                // code is logged. No id or text is ever included.
                tracing::warn!(reason = reason.code(), "dingtalk callback ignored");
                Ok(InboundOutcome::Ignore)
            }
        }
    }
}

#[async_trait]
impl ChannelDelivery for DingTalkChannelAdapter {
    async fn deliver(
        &self,
        envelope: OutboundEnvelope,
        egress: &dyn RestrictedEgress,
    ) -> Result<DeliveryReport, ChannelError> {
        if envelope.parts.is_empty() {
            return Err(ChannelError::Render {
                reason: "outbound envelope carries no parts".to_string(),
            });
        }
        Ok(DeliveryReport::from_parts(
            crate::send::send_parts(&envelope, egress).await,
        ))
    }
}

#[cfg(test)]
#[path = "tests/inbound.rs"]
mod inbound_tests;

#[cfg(test)]
#[path = "tests/channel_conformance.rs"]
mod conformance_tests;

#[cfg(test)]
#[path = "tests/manifest.rs"]
mod manifest_tests;
