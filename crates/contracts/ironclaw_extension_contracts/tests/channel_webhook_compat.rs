//! Pins that the acme webhook and a session channel declaration parse and
//! re-serialize to the exact descriptors recorded before the ingress
//! transport became a tagged enum (stream-ingress Task 3). The snapshots were
//! captured from the pre-refactor code, so a drift in either direction (parse
//! or serialize) fails here.

use ironclaw_extension_contracts::channel::ChannelDescriptor;

const ACME: &str =
    include_str!("../../../../tests/fixtures/extensions/acme-messenger/manifest.toml");
const SESSION_CHANNEL: &str = r#"
id = "session"
display_name = "Session"
conversation_model = "continuous"
[ingress]
body_limit_bytes = 4096
[ingress.verification]
kind = "authenticated_session"
"#;

fn channel_of(manifest: &str) -> ChannelDescriptor {
    let table: toml::Table = toml::from_str(manifest).expect("manifest is valid TOML");
    let channel = table
        .get("channel")
        .cloned()
        .expect("manifest declares a [channel]");
    channel
        .try_into()
        .expect("channel section deserializes into a descriptor")
}

fn assert_matches_snapshot(name: &str, snapshot: &str, channel: &ChannelDescriptor) {
    let actual = serde_json::to_value(channel).expect("descriptor serializes");
    let expected: serde_json::Value =
        serde_json::from_str(snapshot).unwrap_or_else(|error| panic!("{name} snapshot: {error}"));
    assert_eq!(actual, expected, "{name} serialization drifted");
    let reparsed: ChannelDescriptor =
        serde_json::from_value(expected).expect("snapshot deserializes back");
    assert_eq!(&reparsed, channel, "{name} parse drifted from the snapshot");
    channel.validate().expect("shipped channel validates");
}

#[test]
fn acme_webhook_channel_descriptor_is_unchanged() {
    assert_matches_snapshot(
        "acme",
        include_str!("snapshots/acme_channel.json"),
        &channel_of(ACME),
    );
}

#[test]
fn authenticated_session_channel_descriptor_is_unchanged() {
    let channel: ChannelDescriptor =
        toml::from_str(SESSION_CHANNEL).expect("session channel deserializes");
    assert_matches_snapshot(
        "session",
        include_str!("snapshots/session_channel.json"),
        &channel,
    );
}
