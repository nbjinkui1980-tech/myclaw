//! Behavior tests for the witness-gated protocol-auth evidence seal
//! (PROPOSAL §11.2.5, CHECKLIST WS1's evidence-mint row).
//!
//! These live under `tests/` (not an inline `#[cfg(test)]` module) for exactly
//! the reason `tests/authorized_seal.rs` does: minting requires implementing
//! `HostProtocolAuthenticator` or `ChannelIngressVerifier`, and
//! `reborn_sealed_evidence_mint_ratchet` bans those impls outside the one
//! production crate sanctioned for each. A test double under `tests/` is not
//! inventoried by that ratchet, so this is where the seal's own stand-in
//! minters belong — and keeping the ratchet free of a `#[cfg(test)]` carve-out
//! means an inline test module cannot become a hiding place for a grant source.

use ironclaw_host_api::ids::TenantId;
use ironclaw_host_api::product_adapter::auth::{
    AuthRequirement, ChannelIngressVerifier, HostAuthenticationGrant, HostProtocolAuthenticator,
    ProtocolAuthEvidence, VerifiedInboundGrant, mark_bearer_token_verified_for_tenant,
};

/// Stands in for `ironclaw_webui`'s authentication middleware, whose real
/// (and only) implementation sits on a module-private `AuthLayerState`.
struct TestHostAuthenticator;
impl HostProtocolAuthenticator for TestHostAuthenticator {}

/// Stands in for `ironclaw_extension_host`'s generic ingress verifier.
struct TestIngressVerifier;
impl ChannelIngressVerifier for TestIngressVerifier {}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("tenant")
}

/// ✎ **WS8, 2026-08-05:** this used to exercise `mark_bearer_token_verified`
/// too, and a sibling `session_mint_requires_a_host_authentication_grant`
/// exercised both session mints. All three had zero callers in any build and
/// were deleted as dead mint surface, so the tests lost their subjects rather
/// than their assertions: `mark_bearer_token_verified_for_tenant` is the whole
/// surviving bearer/session half, and it carries every property the deleted
/// half did except "an unscoped mint carries no tenant" — which
/// `auth.rs`'s inline `verified_can_only_be_constructed_via_host_helper_inside_crate`
/// still pins on the crate-private constructor underneath.
#[test]
fn bearer_mint_requires_a_host_authentication_grant() {
    let authenticator = TestHostAuthenticator;

    let scoped = mark_bearer_token_verified_for_tenant(
        authenticator.host_authentication_grant(),
        "alice",
        tenant(),
    );
    assert!(scoped.is_verified());
    let claim = scoped.claim().expect("claim");
    assert_eq!(claim.requirement(), &AuthRequirement::BearerToken);
    assert_eq!(claim.subject(), "alice");
    assert_eq!(claim.tenant_id(), Some(&tenant()));
}

/// The cross-crate seam `ironclaw_extension_contracts::verified_inbound` uses.
/// It must carry the requirement and tenant through verbatim — the evidence a
/// channel package sees has to describe the recipe the router actually
/// executed, not a normalized approximation of it.
#[test]
fn verified_inbound_seal_requires_a_verifier_grant_and_preserves_its_inputs() {
    let verifier = TestIngressVerifier;
    let requirement = AuthRequirement::RequestSignature {
        header_name: "X-Slack-Signature".into(),
        timestamp_header_name: Some("X-Slack-Request-Timestamp".into()),
    };

    let evidence = ProtocolAuthEvidence::seal_verified_inbound(
        verifier.verified_inbound_grant(),
        requirement.clone(),
        "T01ABCDEF",
        None,
    );
    assert!(evidence.is_verified());
    let claim = evidence.claim().expect("claim");
    assert_eq!(claim.requirement(), &requirement);
    assert_eq!(claim.subject(), "T01ABCDEF");
    assert!(claim.tenant_id().is_none());

    let scoped = ProtocolAuthEvidence::seal_verified_inbound(
        verifier.verified_inbound_grant(),
        AuthRequirement::SharedSecretHeader {
            header_name: "X-Telegram-Bot-Api-Secret-Token".into(),
        },
        "bot-1",
        Some(tenant()),
    );
    assert_eq!(scoped.claim().expect("claim").tenant_id(), Some(&tenant()));
}

/// The two grants are distinct types, so the bearer minter cannot stand in for
/// the ingress verifier or vice versa. That separation is a *compile-time*
/// property; this pins that the two are never collapsed into one alias, which
/// would silently merge two trust roles.
#[test]
fn the_two_grants_are_distinct_zero_sized_witnesses() {
    assert_eq!(std::mem::size_of::<HostAuthenticationGrant>(), 0);
    assert_eq!(std::mem::size_of::<VerifiedInboundGrant>(), 0);
    assert_ne!(
        std::any::TypeId::of::<HostAuthenticationGrant>(),
        std::any::TypeId::of::<VerifiedInboundGrant>(),
        "collapsing the two grants would let the host authenticator mint channel evidence and the \
         ingress verifier mint bearer evidence"
    );
}

/// Minted evidence must never round-trip back in from the wire: an attacker who
/// can post a body must not be able to post a *verified* claim. `auth.rs`'s
/// inline suite pins this for the crate-private constructors; this pins that
/// the grant-gated entry points inherit it, which is what a caller across the
/// crate boundary actually reaches.
#[test]
fn grant_minted_evidence_does_not_round_trip_back_from_the_wire() {
    let authenticator = TestHostAuthenticator;
    let evidence = mark_bearer_token_verified_for_tenant(
        authenticator.host_authentication_grant(),
        "alice",
        tenant(),
    );

    let json = serde_json::to_string(&evidence).expect("serialize");
    assert!(json.contains("\"verified\""));
    assert!(!json.contains("seal"));
    let parsed: Result<ProtocolAuthEvidence, _> = serde_json::from_str(&json);
    assert!(
        parsed.is_err(),
        "a verified claim must not be reconstructible from wire input"
    );
}

/// Connection-level evidence (`AuthenticatedStream`) goes through the same
/// grant-gated seam as the request-level recipes: it carries the requirement
/// and subject verbatim and takes no tenant of its own.
#[test]
fn authenticated_stream_seal_requires_a_verifier_grant_and_preserves_its_inputs() {
    let verifier = TestIngressVerifier;
    let requirement = AuthRequirement::AuthenticatedStream {
        connection_recipe: "connect".into(),
    };

    let evidence = ProtocolAuthEvidence::seal_verified_inbound(
        verifier.verified_inbound_grant(),
        requirement.clone(),
        "installation-1",
        None,
    );
    assert!(evidence.is_verified());
    let claim = evidence.claim().expect("claim");
    assert_eq!(claim.requirement(), &requirement);
    assert_eq!(claim.subject(), "installation-1");
    assert!(claim.tenant_id().is_none());
}

#[test]
fn authenticated_stream_metadata_accepts_a_plain_recipe_label() {
    for label in [
        "connect",
        "stream_connect",
        "open-connection",
        "a",
        &"x".repeat(64),
    ] {
        AuthRequirement::AuthenticatedStream {
            connection_recipe: label.to_string(),
        }
        .validate_metadata()
        .unwrap_or_else(|error| panic!("label {label:?} must be accepted: {error:?}"));
    }
}

/// The recipe label is a fixed tag, never a place for connection material: a
/// ticket, a URL, a query string, or anything with separators must not fit.
#[test]
fn authenticated_stream_metadata_rejects_labels_that_could_carry_connection_material() {
    for label in [
        "",
        " ",
        "connect\r\nInjected",
        "wss://gateway.example/ws?ticket=abc",
        "ticket=abc",
        "connect?ticket=abc",
        "a/b",
        "a b",
        "a:b",
        "caf\u{e9}",
        &"x".repeat(65),
    ] {
        assert!(
            AuthRequirement::AuthenticatedStream {
                connection_recipe: label.to_string(),
            }
            .validate_metadata()
            .is_err(),
            "label {label:?} must be rejected"
        );
    }
}

#[test]
fn authenticated_stream_requirement_serializes_as_a_snake_case_variant() {
    let requirement = AuthRequirement::AuthenticatedStream {
        connection_recipe: "connect".into(),
    };
    assert_eq!(
        serde_json::to_value(&requirement).expect("serialize"),
        serde_json::json!({"authenticated_stream": {"connection_recipe": "connect"}})
    );
}

/// Negative: stream evidence minted through the grant seam still never
/// round-trips back in from the wire, and a forged `verified` payload naming
/// the new requirement is refused like every other.
#[test]
fn authenticated_stream_evidence_cannot_be_reconstructed_from_the_wire() {
    let verifier = TestIngressVerifier;
    let evidence = ProtocolAuthEvidence::seal_verified_inbound(
        verifier.verified_inbound_grant(),
        AuthRequirement::AuthenticatedStream {
            connection_recipe: "connect".into(),
        },
        "installation-1",
        None,
    );
    let json = serde_json::to_string(&evidence).expect("serialize");
    assert!(json.contains("\"verified\""));
    assert!(json.contains("authenticated_stream"));
    assert!(serde_json::from_str::<ProtocolAuthEvidence>(&json).is_err());

    let forged = serde_json::json!({
        "kind": "verified",
        "claim": {
            "requirement": {"authenticated_stream": {"connection_recipe": "connect"}},
            "subject": "attacker"
        }
    })
    .to_string();
    assert!(serde_json::from_str::<ProtocolAuthEvidence>(&forged).is_err());
}

/// Negative: the verifier grant stays a non-`Clone`, non-`Default`,
/// non-deserializable witness. Adding the stream mint must not make the grant
/// copyable, constructible from nothing, or decodable from untrusted input
/// (ADR section 3: "do not add a third grant").
#[test]
fn the_verifier_grant_is_not_clone_default_or_deserializable() {
    use std::marker::PhantomData;

    // The inherent associated const wins over the trait one exactly when the
    // bound holds, so `HOLDS` reports whether `$ty: $bound` on stable Rust.
    macro_rules! holds {
        ($ty:ty, $bound:path) => {{
            struct Check<T>(PhantomData<T>);
            impl<T: $bound> Check<T> {
                #[allow(dead_code)]
                const HOLDS: bool = true;
            }
            #[allow(dead_code)]
            trait Absent {
                const HOLDS: bool = false;
            }
            impl<T> Absent for Check<T> {}
            <Check<$ty>>::HOLDS
        }};
    }
    assert!(!holds!(VerifiedInboundGrant, Clone));
    assert!(!holds!(VerifiedInboundGrant, Default));
    assert!(!holds!(VerifiedInboundGrant, serde::de::DeserializeOwned));
    // Control: the probe does report a bound that does hold, so the three
    // assertions above are not vacuous.
    assert!(holds!(String, Clone));
}
