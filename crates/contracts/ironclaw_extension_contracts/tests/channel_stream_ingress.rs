//! `[channel.ingress.stream]` declaration contract (stream-ingress Task 3):
//! parsing, round-trip, transport exclusivity, and bounds validation.
//! The webhook and session shapes stay pinned by `channel_webhook_compat`.

use ironclaw_extension_contracts::channel::{
    ChannelDescriptor, ChannelDescriptorError, MAX_STREAM_FRAME_BYTES, MAX_STREAM_FRAMES_PER_SECOND,
};

fn stream_channel_toml() -> String {
    r#"
id = "messages"
display_name = "Stream messages"
conversation_model = "continuous"

[reply]
transport = "message"

[connection]
provider = "acme"
strategy = "web_generated_code"
instructions = "Send the code."
input_placeholder = ""
submit_label = "Connect"
error_message = "Failed."
connection_success_message = "Connected."
[connection.notices]
connect_required = "Connect first."
paired = "Paired."
already_paired_same_user = "Already paired."
already_bound_to_other_user = "Bound elsewhere."
expired_or_unknown = "Expired."

[ingress.stream]
url_template = "{endpoint}?ticket={ticket}"
hosts = ["gateway.acme.example"]
max_frame_bytes = 65536
max_frames_per_second = 20

[ingress.stream.connect]
path = "/v1/connections/open"
body_credentials = ["acme_client_secret"]
body = { clientId = "acme-client" }

[ingress.stream.response]
endpoint = "/endpoint"
ticket = "/ticket"

[[ingress.stream.subscriptions]]
type = "CALLBACK"
topic = "/v1/messages/get"

[ingress.stream.keepalive]
ping_interval_secs = 60
pong_timeout_secs = 10

[[egress]]
host = "api.acme.example"
methods = ["post"]
[[egress.body_credentials]]
handle = "acme_client_secret"
pointer = "/clientSecret"
"#
    .to_string()
}
fn parse_stream(toml_text: &str) -> Result<ChannelDescriptor, toml::de::Error> {
    toml::from_str(toml_text)
}
#[test]
fn stream_ingress_parses_validates_and_round_trips() {
    let channel = parse_stream(&stream_channel_toml()).expect("stream channel parses");
    channel.validate().expect("stream channel validates");
    let ingress = channel.ingress.as_ref().expect("ingress");
    assert!(ingress.route_suffix().is_none());
    assert!(ingress.webhook_verification().is_none());
    let stream = ingress.stream().expect("stream transport");
    assert_eq!(stream.hosts, ["gateway.acme.example"]);
    assert_eq!(stream.response.ticket, "/ticket");
    assert_eq!(stream.subscriptions[0].kind, "CALLBACK");
    let json = serde_json::to_string(&channel).unwrap();
    assert!(!json.contains("route_suffix") && !json.contains("\"verification\""));
    let back: ChannelDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, channel);
    // The documented body mechanism is the top-level `subscriptions`
    // injection only: the recipe body never carries a placeholder for it.
    assert!(!stream_channel_toml().contains("{subscriptions}"));
}
#[test]
fn stream_ingress_excludes_webhook_and_session_fields() {
    for extra in [
        "route_suffix = \"events\"\n",
        "[ingress.verification]\nkind = \"none\"\n",
        "[ingress.verification]\nkind = \"authenticated_session\"\n",
        "body_limit_bytes = 65536\n",
    ] {
        let text = stream_channel_toml().replace(
            "[ingress.stream]\n",
            &format!("[ingress]\n{extra}[ingress.stream]\n"),
        );
        let error = parse_stream(&text).expect_err("mixed transports must not parse");
        assert!(
            error
                .to_string()
                .contains(&ChannelDescriptorError::StreamIngressWithWebhookFields.to_string()),
            "{extra}: {error}"
        );
    }
}
#[test]
fn stream_ingress_rejects_each_malformed_field() {
    let cases: [(&str, &str, &str); 12] = [
        (
            "path",
            "path = \"/v1/connections/open\"",
            "path = \"v1/open\"",
        ),
        (
            "pointer",
            "endpoint = \"/endpoint\"",
            "endpoint = \"endpoint\"",
        ),
        (
            "same pointer",
            "ticket = \"/ticket\"",
            "ticket = \"/endpoint\"",
        ),
        (
            "unknown placeholder",
            "{endpoint}?ticket={ticket}",
            "{endpoint}?ticket={ticket}&x={other}",
        ),
        ("missing ticket", "{endpoint}?ticket={ticket}", "{endpoint}"),
        ("wildcard host", "gateway.acme.example", "*.acme.example"),
        (
            "uppercase host",
            "gateway.acme.example",
            "Gateway.acme.example",
        ),
        (
            "host with port",
            "gateway.acme.example",
            "gateway.acme.example:443",
        ),
        (
            "zero ping",
            "ping_interval_secs = 60",
            "ping_interval_secs = 0",
        ),
        (
            "huge pong",
            "pong_timeout_secs = 10",
            "pong_timeout_secs = 100000",
        ),
        (
            "huge frame",
            "max_frame_bytes = 65536",
            "max_frame_bytes = 999999999",
        ),
        (
            "huge rate",
            "max_frames_per_second = 20",
            "max_frames_per_second = 1000000",
        ),
    ];
    for (label, from, to) in cases {
        let text = stream_channel_toml().replace(from, to);
        assert_ne!(text, stream_channel_toml(), "{label}: replacement missed");
        let channel = parse_stream(&text).expect("shape parses; bounds are validated");
        assert!(
            matches!(
                channel.validate(),
                Err(ChannelDescriptorError::InvalidStreamIngress { .. })
            ),
            "{label} must be rejected: {:?}",
            channel.validate()
        );
    }
    let no_hosts =
        stream_channel_toml().replace("hosts = [\"gateway.acme.example\"]", "hosts = []");
    assert!(matches!(
        parse_stream(&no_hosts).unwrap().validate(),
        Err(ChannelDescriptorError::InvalidStreamIngress { field: "hosts" })
    ));
    let missing_stream_field = stream_channel_toml().replace("max_frame_bytes = 65536\n", "");
    assert!(
        parse_stream(&missing_stream_field).is_err(),
        "missing field"
    );
    let unknown = stream_channel_toml().replace(
        "[ingress.stream.keepalive]",
        "wire = 1\n[ingress.stream.keepalive]",
    );
    assert!(parse_stream(&unknown).is_err(), "unknown field");
}
#[test]
fn stream_ingress_allows_a_connection_and_still_rejects_wss_egress() {
    let channel = parse_stream(&stream_channel_toml()).unwrap();
    assert!(channel.connection.is_some());
    channel
        .validate()
        .expect("connection is allowed on stream ingress");
    let wss = stream_channel_toml().replace(
        "host = \"api.acme.example\"",
        "scheme = \"wss\"\nhost = \"api.acme.example\"",
    );
    assert!(matches!(
        parse_stream(&wss).unwrap().validate(),
        Err(ChannelDescriptorError::UnsupportedEgressScheme { .. })
    ));
}

fn validation_field(text: &str) -> Option<&'static str> {
    match parse_stream(text).expect("shape parses").validate() {
        Err(ChannelDescriptorError::InvalidStreamIngress { field }) => Some(field),
        Ok(()) => None,
        Err(other) => panic!("unexpected error: {other}"),
    }
}
#[test]
fn declared_frame_limit_stops_at_the_network_ceiling() {
    // Review #2: 1 MiB is the most the network layer enforces.
    assert_eq!(MAX_STREAM_FRAME_BYTES, 1024 * 1024);
    let at = stream_channel_toml().replace("max_frame_bytes = 65536", "max_frame_bytes = 1048576");
    assert_eq!(validation_field(&at), None, "exactly the ceiling passes");
    let above =
        stream_channel_toml().replace("max_frame_bytes = 65536", "max_frame_bytes = 1048577");
    assert_eq!(validation_field(&above), Some("max_frame_bytes"));
    let four_mib =
        stream_channel_toml().replace("max_frame_bytes = 65536", "max_frame_bytes = 4194304");
    assert_eq!(
        validation_field(&four_mib),
        Some("max_frame_bytes"),
        "a manifest above the network ceiling fails at validation, not at runtime"
    );
}
#[test]
fn declared_frame_rate_keeps_two_x_headroom_under_the_network_ceiling() {
    // Review #11: the hard cap is twice the declared rate, so the declared
    // maximum is half of the network layer's 1000/s ceiling.
    assert_eq!(MAX_STREAM_FRAMES_PER_SECOND, 500);
    let at =
        stream_channel_toml().replace("max_frames_per_second = 20", "max_frames_per_second = 500");
    assert_eq!(validation_field(&at), None);
    let above =
        stream_channel_toml().replace("max_frames_per_second = 20", "max_frames_per_second = 501");
    assert_eq!(validation_field(&above), Some("max_frames_per_second"));
}
#[test]
fn url_template_must_start_with_the_validated_endpoint() {
    // Review #9: a foreign authority is rejected at install time.
    for template in [
        "wss://attacker.example/?e={endpoint}&t={ticket}",
        "wss://attacker.example/{endpoint}?ticket={ticket}",
        "?ticket={ticket}&e={endpoint}",
        "x{endpoint}?ticket={ticket}",
    ] {
        let text = stream_channel_toml().replace("{endpoint}?ticket={ticket}", template);
        assert_eq!(validation_field(&text), Some("url_template"), "{template}");
    }
    let ok = stream_channel_toml().replace(
        "{endpoint}?ticket={ticket}",
        "{endpoint}/v2?ticket={ticket}",
    );
    assert_eq!(validation_field(&ok), None);
}
#[test]
fn url_template_text_after_the_endpoint_cannot_extend_the_authority() {
    // Review: `{endpoint}.evil.example` would name another host.
    for template in [
        "{endpoint}.evil.example/x?ticket={ticket}",
        "{endpoint}@evil.example/x?ticket={ticket}",
        "{endpoint}:444/x?ticket={ticket}",
    ] {
        let text = stream_channel_toml().replace("{endpoint}?ticket={ticket}", template);
        assert_eq!(validation_field(&text), Some("url_template"), "{template}");
    }
}
#[test]
fn url_template_keeps_the_ticket_in_the_query() {
    // Review N2: a ticket outside the query would reach URL parsing, policy
    // evaluation and unscrubbed path storage.
    for template in [
        "{endpoint}/{ticket}",
        "{endpoint}/{ticket}?x=1",
        "{endpoint}{ticket}",
    ] {
        let text = stream_channel_toml().replace("{endpoint}?ticket={ticket}", template);
        assert_eq!(validation_field(&text), Some("url_template"), "{template}");
    }
}
