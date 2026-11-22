//! `[channel.egress.credential_source]` declaration contract (token exchange,
//! milestone 1b Task 11): parsing, round-trip, mutual exclusion with the
//! static credential fields, pointer/header bounds, and the rule that the
//! exchange endpoint is itself a declared egress target.
use ironclaw_extension_contracts::channel::{ChannelDescriptor, ChannelDescriptorError};

const VALID: &str = r#"
id = "messages"
display_name = "Token messages"
conversation_model = "continuous"
[reply]
transport = "message"

[[egress]]
host = "auth.acme.example"
methods = ["post"]
paths = ["/v1/oauth/token"]
[[egress.body_credentials]]
handle = "acme_app_key"
pointer = "/appKey"
[[egress.body_credentials]]
handle = "acme_app_secret"
pointer = "/appSecret"

[[egress]]
host = "api.acme.example"
methods = ["post"]
paths = ["/v1/messages"]
[egress.credential_source]
handle = "acme_access_token"
exchange_host = "auth.acme.example"
token_pointer = "/accessToken"
expires_in_pointer = "/expireIn"
[egress.credential_source.exchange]
method = "post"
path = "/v1/oauth/token"
body = { grant = "client" }
body_credentials = ["acme_app_key", "acme_app_secret"]
[egress.credential_source.header]
name = "x-acme-access-token"
prefix = "Token "
"#;

fn mutate(from: &str, to: &str) -> String {
    assert!(VALID.contains(from), "fixture lacks `{from}`");
    VALID.replacen(from, to, 1)
}

fn validate(toml_text: &str) -> Result<(), ChannelDescriptorError> {
    let channel: ChannelDescriptor = toml::from_str(toml_text).expect("fixture parses");
    channel.validate()
}

fn expect_field(toml_text: &str, expected: &'static str) {
    match validate(toml_text) {
        Err(ChannelDescriptorError::InvalidCredentialSource { field, .. }) => {
            assert_eq!(field, expected, "wrong field for rejected declaration");
        }
        other => panic!("expected InvalidCredentialSource({expected}), got {other:?}"),
    }
}

#[test]
fn a_valid_declaration_parses_validates_and_round_trips() {
    let channel: ChannelDescriptor = toml::from_str(VALID).expect("parses");
    channel.validate().expect("validates");
    let source = channel.egress[1]
        .credential_source
        .as_ref()
        .expect("source declared");
    assert_eq!(source.handle.as_str(), "acme_access_token");
    assert_eq!(source.header.name, "x-acme-access-token");
    assert_eq!(source.header.prefix.as_deref(), Some("Token "));
    assert!(channel.egress[0].credential_source.is_none());
    let json = serde_json::to_string(&channel).unwrap();
    let again: ChannelDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(again, channel);
    assert_eq!(serde_json::to_string(&again).unwrap(), json);
}

#[test]
fn descriptors_without_a_source_serialize_without_the_field() {
    let channel: ChannelDescriptor = toml::from_str(VALID).unwrap();
    let mut without = channel.clone();
    without.egress[1].credential_source = None;
    assert!(
        !serde_json::to_string(&without)
            .unwrap()
            .contains("credential_source")
    );
}

#[test]
fn a_source_excludes_every_static_credential_declaration() {
    for extra in [
        "credential_handle = \"acme_static\"\n",
        "injection = { type = \"header\", name = \"x-k\" }\ncredential_handle = \"acme_static\"\n",
    ] {
        let text = mutate(
            "paths = [\"/v1/messages\"]\n",
            &format!("paths = [\"/v1/messages\"]\n{extra}"),
        );
        assert!(
            matches!(
                validate(&text),
                Err(ChannelDescriptorError::CredentialSourceWithStaticCredential { .. })
            ),
            "static credential beside a source must be rejected: {extra}"
        );
    }
    let text = VALID.replacen(
        "[egress.credential_source]\n",
        "[[egress.body_credentials]]\nhandle = \"acme_other\"\npointer = \"/other\"\n[egress.credential_source]\n",
        1,
    );
    assert!(matches!(
        validate(&text),
        Err(ChannelDescriptorError::CredentialSourceWithStaticCredential { .. })
    ));
}

#[test]
fn a_missing_expiry_pointer_does_not_deserialize() {
    let text = mutate("expires_in_pointer = \"/expireIn\"\n", "");
    assert!(toml::from_str::<ChannelDescriptor>(&text).is_err());
}

#[test]
fn unknown_source_fields_do_not_deserialize() {
    let text = mutate(
        "token_pointer = \"/accessToken\"\n",
        "token_pointer = \"/accessToken\"\nvendor_hint = \"x\"\n",
    );
    assert!(toml::from_str::<ChannelDescriptor>(&text).is_err());
}

#[test]
fn pointers_must_be_bounded_distinct_json_pointers() {
    expect_field(
        &mutate(
            "token_pointer = \"/accessToken\"",
            "token_pointer = \"accessToken\"",
        ),
        "token_pointer",
    );
    expect_field(
        &mutate("token_pointer = \"/accessToken\"", "token_pointer = \"\""),
        "token_pointer",
    );
    expect_field(
        &mutate(
            "expires_in_pointer = \"/expireIn\"",
            "expires_in_pointer = \"/a~2b\"",
        ),
        "expires_in_pointer",
    );
    expect_field(
        &mutate(
            "expires_in_pointer = \"/expireIn\"",
            &format!("expires_in_pointer = \"/{}\"", "x".repeat(300)),
        ),
        "expires_in_pointer",
    );
    expect_field(
        &mutate(
            "expires_in_pointer = \"/expireIn\"",
            "expires_in_pointer = \"/accessToken\"",
        ),
        "expires_in_pointer",
    );
}

#[test]
fn the_exchange_path_must_be_a_plain_rooted_path() {
    for path in ["v1/oauth/token", "/v1/oauth/token?x=1", "/v1/../token"] {
        let text = mutate(
            "path = \"/v1/oauth/token\"\nbody",
            &format!("path = \"{path}\"\nbody"),
        );
        expect_field(&text, "exchange.path");
    }
}

#[test]
fn the_exchange_must_carry_host_injected_app_credentials() {
    expect_field(
        &mutate(
            "body_credentials = [\"acme_app_key\", \"acme_app_secret\"]",
            "body_credentials = []",
        ),
        "exchange.body_credentials",
    );
    expect_field(
        &mutate(
            "body_credentials = [\"acme_app_key\", \"acme_app_secret\"]",
            "body_credentials = [\"acme_access_token\"]",
        ),
        "exchange.body_credentials",
    );
    expect_field(
        &mutate(
            "body_credentials = [\"acme_app_key\", \"acme_app_secret\"]",
            "body_credentials = [\"acme_app_key\", \"acme_app_key\"]",
        ),
        "exchange.body_credentials",
    );
}

#[test]
fn the_exchange_body_is_a_static_object_without_placeholders() {
    expect_field(
        &mutate(
            "body = { grant = \"client\" }",
            "body = { grant = \"{cfg}\" }",
        ),
        "exchange.body",
    );
    expect_field(
        &mutate("body = { grant = \"client\" }", "body = [\"client\"]"),
        "exchange.body",
    );
}

#[test]
fn the_header_must_be_a_host_owned_safe_header() {
    for name in [
        "X-Upper",
        "",
        "host",
        "content-length",
        "transfer-encoding",
        "cookie",
        "proxy-authorization",
    ] {
        expect_field(
            &mutate(
                "name = \"x-acme-access-token\"",
                &format!("name = \"{name}\""),
            ),
            "header.name",
        );
    }
    validate(&mutate(
        "name = \"x-acme-access-token\"",
        "name = \"authorization\"",
    ))
    .expect("authorization is the host-owned injection header");
    expect_field(
        &mutate(
            "prefix = \"Token \"",
            &format!("prefix = \"{}\"", "p".repeat(33)),
        ),
        "header.prefix",
    );
    expect_field(
        &mutate("prefix = \"Token \"", "prefix = \"a\\nb\""),
        "header.prefix",
    );
}

#[test]
fn the_exchange_endpoint_must_be_a_declared_egress_target() {
    // Host not declared.
    expect_field(
        &mutate(
            "exchange_host = \"auth.acme.example\"",
            "exchange_host = \"evil.example\"",
        ),
        "exchange_host",
    );
    // Path not declared on the exchange host.
    expect_field(
        &mutate(
            "path = \"/v1/oauth/token\"\nbody",
            "path = \"/v1/other\"\nbody",
        ),
        "exchange_host",
    );
    // Method not declared on the exchange host.
    expect_field(
        &mutate(
            "methods = [\"post\"]\npaths = [\"/v1/oauth/token\"]",
            "methods = [\"get\"]\npaths = [\"/v1/oauth/token\"]",
        ),
        "exchange_host",
    );
    // Only a POST exchange can carry the app credentials in a JSON body.
    expect_field(
        &mutate("method = \"post\"\npath", "method = \"get\"\npath"),
        "exchange.method",
    );
    // The exchange host is the source target itself (not "another" target).
    expect_field(
        &mutate(
            "exchange_host = \"auth.acme.example\"",
            "exchange_host = \"api.acme.example\"",
        ),
        "exchange_host",
    );
    // The exchange target lacks a declared pointer for one handle.
    expect_field(
        &mutate(
            "[[egress.body_credentials]]\nhandle = \"acme_app_secret\"\npointer = \"/appSecret\"\n",
            "",
        ),
        "exchange.body_credentials",
    );
    // Legacy host+method-only targets do not count as declaring the path.
    expect_field(
        &mutate("paths = [\"/v1/oauth/token\"]\n", ""),
        "exchange_host",
    );
}

#[test]
fn the_exchange_endpoint_may_be_declared_by_prefix_but_not_twice() {
    let prefixed = mutate(
        "paths = [\"/v1/oauth/token\"]",
        "path_prefixes = [\"/v1/oauth/\"]",
    );
    validate(&prefixed).expect("a path prefix declares the exchange path");
    let duplicated = VALID.replacen(
        "[[egress]]\nhost = \"api.acme.example\"",
        "[[egress]]\nhost = \"AUTH.acme.example\"\nmethods = [\"post\"]\npaths = [\"/v1/oauth/token\"]\n[[egress.body_credentials]]\nhandle = \"acme_app_key\"\npointer = \"/appKey\"\n[[egress.body_credentials]]\nhandle = \"acme_app_secret\"\npointer = \"/appSecret\"\n\n[[egress]]\nhost = \"api.acme.example\"",
        1,
    );
    expect_field(&duplicated, "exchange_host");
}

#[test]
fn the_exchange_target_must_not_itself_use_a_source() {
    let chained = VALID.replacen(
        "[[egress.body_credentials]]\nhandle = \"acme_app_key\"",
        "[egress.credential_source]\nhandle = \"acme_inner\"\nexchange_host = \"api.acme.example\"\ntoken_pointer = \"/t\"\nexpires_in_pointer = \"/e\"\n[egress.credential_source.exchange]\nmethod = \"post\"\npath = \"/v1/messages\"\nbody_credentials = [\"acme_app_key\"]\n[egress.credential_source.header]\nname = \"x-inner\"\n[[egress.body_credentials]]\nhandle = \"acme_app_key\"",
        1,
    );
    assert!(
        validate(&chained).is_err(),
        "chained sources must be rejected"
    );
}

#[test]
fn the_token_handle_must_not_collide_with_another_declared_handle() {
    expect_field(
        &mutate(
            "handle = \"acme_access_token\"",
            "handle = \"acme_app_key\"",
        ),
        "handle",
    );
}

#[test]
fn the_exchange_target_must_be_https() {
    expect_field(
        &mutate(
            "host = \"auth.acme.example\"\nmethods",
            "scheme = \"http\"\nhost = \"auth.acme.example\"\nmethods",
        ),
        "exchange_host",
    );
}
