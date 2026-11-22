//! TEST-1: the DingTalk adapter runs the exported conformance contracts, both
//! the ingress half and the stream frame-control half, against the
//! constructed frames in `tests/fixtures/extensions/dingtalk-stream/`.
use std::path::PathBuf;
use std::sync::Arc;

use crate::channel::DingTalkChannelAdapter;
use crate::reply_context::{DingTalkConversationKind, DingTalkReplyContext};
use crate::stream::DingTalkStreamControl;
use ironclaw_extension_contracts::channel::ReplyTransport;
use ironclaw_extension_contracts::channel_adapter::ChannelSurfaces;
use ironclaw_extension_contracts::channel_adapter::{
    OutboundEnvelope, OutboundPart, OutboundTarget, OutboundVisibility,
};
use ironclaw_extension_contracts::external::ExternalConversationRef;
use ironclaw_extension_contracts::test_support::conformance::{
    ChannelAdapterConformance, ConformanceInbound, StreamControlConformance,
    run_channel_adapter_conformance, run_stream_control_conformance,
};
use ironclaw_extension_contracts::tool_adapter::RestrictedEgressResponse;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../tests/fixtures/extensions/dingtalk-stream")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn surfaces() -> ChannelSurfaces {
    let adapter = Arc::new(DingTalkChannelAdapter::default());
    ChannelSurfaces::default()
        .with_ingress(adapter.clone())
        .with_delivery(adapter.clone())
        .with_reply(adapter)
        .with_stream_control(Arc::new(DingTalkStreamControl))
}

fn callback_data() -> Vec<u8> {
    let frame: serde_json::Value =
        serde_json::from_slice(&fixture("callback_single_chat_text.json")).expect("fixture");
    frame["data"].as_str().expect("data").as_bytes().to_vec()
}

#[tokio::test]
async fn dingtalk_adapter_satisfies_the_channel_conformance_contract() {
    run_channel_adapter_conformance(ChannelAdapterConformance {
        surfaces: surfaces(),
        // The manifest's `[channel.reply] transport`.
        reply_transport: Some(ReplyTransport::Message),
        extension_id: "dingtalk".to_string(),
        installation_id: "install_alpha".to_string(),
        message_inbound: Some(ConformanceInbound {
            body: callback_data(),
            headers: Vec::new(),
        }),
        challenge_inbound: None,
        outbound_envelope: OutboundEnvelope {
            target: OutboundTarget {
                conversation: ExternalConversationRef::new(None, "cidREDACTED", None, None)
                    .expect("conversation"),
                thread_anchor: None,
            },
            parts: vec![OutboundPart::Text("conformance notice".to_string())],
            reply_context: Some(
                DingTalkReplyContext::new(
                    DingTalkConversationKind::Dm,
                    "cidREDACTED",
                    "REDACTED_STAFF_ID",
                    Some("REDACTED_ROBOT_CODE".to_string()),
                )
                .encode()
                .expect("context"),
            ),
            registrations: Vec::new(),
            visibility: OutboundVisibility::Public,
        },
        vendor_responses: Arc::new(|_request| RestrictedEgressResponse {
            retry_after: None,
            status: 200,
            body: br#"{"processQueryKey":"pqk-conformance"}"#.to_vec(),
        }),
        config: Vec::new(),
    })
    .await;
}

#[tokio::test]
async fn dingtalk_frame_control_satisfies_the_stream_conformance_contract() {
    run_stream_control_conformance(StreamControlConformance {
        surfaces: surfaces(),
        extension_id: "dingtalk".to_string(),
        installation_id: "install_alpha".to_string(),
        config: Vec::new(),
        event_frame: fixture("callback_single_chat_text.json"),
        reconnect_frame: Some(fixture("system_disconnect.json")),
        vendor_responses: Arc::new(|_request| RestrictedEgressResponse {
            retry_after: None,
            status: 500,
            body: Vec::new(),
        }),
    })
    .await;
}
