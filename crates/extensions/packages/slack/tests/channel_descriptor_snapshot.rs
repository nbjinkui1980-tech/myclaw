//! Pins that the shipped slack `[channel]` declaration parses and
//! re-serializes to the exact descriptor recorded before the ingress
//! transport became a tagged enum (stream-ingress Task 3). The snapshot was
//! captured from the pre-refactor code.

use ironclaw_extension_contracts::channel::ChannelDescriptor;

const MANIFEST: &str = include_str!("../manifest.toml");

#[test]
fn shipped_channel_descriptor_is_unchanged() {
    let table: toml::Table = toml::from_str(MANIFEST).expect("manifest is valid TOML");
    let channel: ChannelDescriptor = table
        .get("channel")
        .cloned()
        .expect("manifest declares a [channel]")
        .try_into()
        .expect("channel section deserializes into a descriptor");
    let actual = serde_json::to_value(&channel).expect("descriptor serializes");
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("snapshots/channel.json")).expect("snapshot is JSON");
    assert_eq!(actual, expected, "shipped channel serialization drifted");
    let reparsed: ChannelDescriptor =
        serde_json::from_value(expected).expect("snapshot deserializes back");
    assert_eq!(
        reparsed, channel,
        "shipped channel parse drifted from the snapshot"
    );
    channel.validate().expect("shipped channel validates");
}
