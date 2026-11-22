//! Pins the shipped `[channel]` declaration: one organisation per deployment,
//! credentials only as secret admin fields, exactly one gateway host.
use ironclaw_extension_contracts::channel::ChannelDescriptor;

const MANIFEST: &str = include_str!("../../manifest.toml");

fn table() -> toml::Table {
    toml::from_str(MANIFEST).expect("manifest is valid TOML")
}

fn channel() -> ChannelDescriptor {
    table()
        .get("channel")
        .cloned()
        .expect("manifest declares a [channel]")
        .try_into()
        .expect("channel section deserializes into a descriptor")
}

#[test]
fn channel_validates_and_declares_a_stream_ingress_on_one_exact_host() {
    let channel = channel();
    channel.validate().expect("shipped channel validates");
    let ingress = channel.ingress.as_ref().expect("ingress");
    let stream = ingress.stream().expect("stream transport");
    // ADR 1.2: exact hosts only. UNVERIFIED (ADR §8 item 5, Task 20): the
    // gateway host name comes from the operator's decision, not a probe.
    assert_eq!(stream.hosts, ["wss-open-connection.dingtalk.com"]);
    assert_eq!(stream.connect.path, "/v1.0/gateway/connections/open");
    assert_eq!(
        stream.connect.body_credentials.len(),
        2,
        "clientId and clientSecret are both injected host-side"
    );
    assert!(stream.url_template.starts_with("{endpoint}?"));
}

#[test]
fn admin_credentials_are_secret_required_fields() {
    let manifest = table();
    let fields = manifest["admin_configuration"]["fields"]
        .as_array()
        .expect("fields");
    for handle in ["dingtalk_client_id", "dingtalk_client_secret"] {
        let field = fields
            .iter()
            .find(|f| f["handle"].as_str() == Some(handle))
            .unwrap_or_else(|| panic!("{handle} is declared"));
        assert_eq!(field["secret"].as_bool(), Some(true), "{handle} is secret");
        assert_eq!(field["required"].as_bool(), Some(true));
    }
    assert_eq!(fields.len(), 2, "operators fill in exactly two values");
}

#[test]
fn sends_use_a_host_exchanged_token_and_declared_send_paths() {
    let channel = channel();
    let send = channel
        .egress
        .iter()
        .find(|egress| {
            egress
                .paths
                .iter()
                .any(|path| path == "/v1.0/robot/oToMessages/batchSend")
        })
        .expect("a send target is declared");
    assert_eq!(
        send.paths,
        [
            "/v1.0/robot/oToMessages/batchSend",
            "/v1.0/robot/groupMessages/send"
        ]
    );
    let source = send.credential_source.as_ref().expect("token source");
    assert_eq!(source.handle.as_str(), "dingtalk_access_token");
    assert_eq!(source.exchange_host, "api.dingtalk.com");
    assert_eq!(source.exchange.path, "/v1.0/oauth2/accessToken");
    assert_eq!(source.token_pointer, "/accessToken");
    assert_eq!(source.expires_in_pointer, "/expireIn");
    assert_eq!(source.header.name, "x-acs-dingtalk-access-token");
    assert!(source.header.prefix.is_none());
    assert!(
        send.body_credentials.is_empty(),
        "a credential_source target carries no body credentials, which is why robotCode comes from the callback"
    );
    let exchange = channel
        .egress
        .iter()
        .find(|egress| egress.paths.iter().any(|p| p == "/v1.0/oauth2/accessToken"))
        .expect("the exchange endpoint is declared");
    let pointers: Vec<(&str, &str)> = exchange
        .body_credentials
        .iter()
        .map(|b| (b.handle.as_str(), b.pointer.as_str()))
        .collect();
    assert_eq!(
        pointers,
        [
            ("dingtalk_client_id", "/appKey"),
            ("dingtalk_client_secret", "/appSecret")
        ]
    );
    assert!(channel.delivery.is_some(), "[channel.delivery] is declared");
    assert_eq!(
        channel.reply_transport(),
        Some(ironclaw_extension_contracts::channel::ReplyTransport::Message),
        "replies are one terminal message"
    );
}

/// Review #1: the connect call's secrets ride the declared body credentials.
/// A target-level `credential_handle` would make the host also set the
/// ClientSecret as an `Authorization: Bearer` header on every connect.
#[test]
fn the_connect_target_carries_no_static_credential() {
    let channel = channel();
    let connect = channel
        .egress
        .iter()
        .find(|egress| {
            egress
                .paths
                .iter()
                .any(|p| p == "/v1.0/gateway/connections/open")
        })
        .expect("the connect endpoint is declared");
    assert!(
        connect.credential_handle.is_none(),
        "the connect target must not name a header credential"
    );
    assert!(connect.credential_source.is_none());
    let pointers: Vec<(&str, &str)> = connect
        .body_credentials
        .iter()
        .map(|b| (b.handle.as_str(), b.pointer.as_str()))
        .collect();
    assert_eq!(
        pointers,
        [
            ("dingtalk_client_id", "/clientId"),
            ("dingtalk_client_secret", "/clientSecret")
        ],
        "clientId and clientSecret are injected into the body"
    );
}
#[test]
fn no_wildcard_hosts_and_no_session_webhook_paths() {
    let channel = channel();
    for egress in &channel.egress {
        assert!(!egress.host.contains('*'), "{}", egress.host);
        assert_eq!(egress.host, "api.dingtalk.com");
        for path in &egress.paths {
            assert!(!path.contains('?'), "{path}");
        }
    }
    assert!(
        !MANIFEST.to_lowercase().contains("sessionwebhook"),
        "replies never use the query-carrying sessionWebhook"
    );
}

#[test]
fn pairing_is_a_web_generated_code_without_deep_link_or_prefixes() {
    let channel = channel();
    let connection = channel.connection.as_ref().expect("[channel.connection]");
    let value = serde_json::to_value(connection).expect("serializes");
    assert_eq!(value["strategy"], "web_generated_code");
    assert_eq!(value["provider"], "dingtalk");
    assert!(
        connection.deep_link_template.is_none(),
        "DingTalk has no start-link"
    );
    assert!(
        connection.inbound_code_prefixes.is_empty(),
        "the user sends the bare code"
    );
    let notices = &connection.notices;
    for notice in [
        &notices.connect_required,
        &notices.paired,
        &notices.already_paired_same_user,
        &notices.already_bound_to_other_user,
        &notices.expired_or_unknown,
    ] {
        assert!(!notice.trim().is_empty());
    }
    assert!(!connection.connection_success_message.trim().is_empty());
}
