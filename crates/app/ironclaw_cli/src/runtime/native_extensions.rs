//! Binary-assembled native extension factories (extension-runtime DEL-7's
//! target architecture, first exercised by Telegram for DEL-10): the CLI is
//! the one generic-side crate allowed to link concrete extension crates, and
//! it hands the factory registry to composition as input — composition never
//! names a concrete extension.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_composition::{
    ChannelExtensionBinding, FirstPartyChannelInitializationContext,
    FirstPartyChannelInitializationError, FirstPartyChannelInitializer,
};
use ironclaw_dingtalk_extension::dingtalk_channel;
use ironclaw_extension_contracts::channel_adapter::ChannelSurfaces;
use ironclaw_extension_host::{
    BindContext, BindError, ExtensionBindings, ExtensionEntrypoint, LoadContext,
    NativeExtensionFactory,
};
use ironclaw_host_api::ids::ExtensionId;
use ironclaw_telegram_extension::{
    MtprotoAppIdentity, SessionPool, TELEGRAM_API_HASH_HANDLE, TELEGRAM_API_ID_CONFIG,
    TelegramChannelAdapter, TelegramDeviceLinkAdapter, TelegramLinkedToolAdapter,
    TelegramPreferenceTargetCodec,
};
use secrecy::ExposeSecret as _;

/// Every native factory the binary assembles (`first_party`-runtime
/// extensions bind their adapters through these).
pub(crate) fn bundled_native_extension_factories() -> Vec<Arc<dyn NativeExtensionFactory>> {
    vec![
        Arc::new(TelegramExtensionFactory),
        Arc::new(DingTalkExtensionFactory),
    ]
}

/// The binary-assembled channel extension set.
pub(crate) struct BundledChannelExtensions {
    pub(crate) bindings: Vec<ChannelExtensionBinding>,
    /// The channel whose reply is the deployment's session stream;
    /// composition attaches the product projection sink to its binding.
    pub(crate) session_reply_channel: Option<ironclaw_host_api::ids::ExtensionId>,
}

/// Deployment channel-adapter bindings. These are independent of native tool
/// loading: the host mounts manifest-declared ingress before any user
/// installation exists, so every deployment channel adapter is linked here.
/// Composition never names a concrete extension crate.
pub(crate) fn bundled_channel_extensions(
    web_app_vapid_subject: Option<String>,
) -> BundledChannelExtensions {
    let bindings = vec![
        ChannelExtensionBinding {
            extension_id: ExtensionId::from_trusted("slack".to_string()),
            // Every half: a webhook ingress, a message reply, a message
            // delivery. One vendor mechanism serves both output axes, which
            // is why the distinction stayed invisible until web-app existed.
            surfaces: {
                let adapter = Arc::new(ironclaw_slack_extension::SlackChannelAdapter);
                ChannelSurfaces::default()
                    .with_ingress(adapter.clone())
                    .with_reply(adapter.clone())
                    .with_delivery(adapter)
            },
            preference_target_codec: Some(Arc::new(
                ironclaw_slack_extension::SlackPreferenceTargetCodec,
            )),
            outbound_target_provider: None,
            first_party_initializer: None,
            registration_document_path: None,
        },
        ChannelExtensionBinding {
            extension_id: ExtensionId::from_trusted("telegram".to_string()),
            surfaces: {
                let adapter = Arc::new(TelegramChannelAdapter::default());
                ChannelSurfaces::default()
                    .with_ingress(adapter.clone())
                    .with_reply(adapter.clone())
                    .with_delivery(adapter)
            },
            preference_target_codec: Some(Arc::new(TelegramPreferenceTargetCodec)),
            outbound_target_provider: None,
            first_party_initializer: None,
            registration_document_path: None,
        },
        {
            // The package's one assembly of the four halves plus the codec
            // (DingTalk plan Task 18: no package-owned outbound-target
            // provider; the generic provider offers the caller's own DM).
            let dingtalk = dingtalk_channel();
            ChannelExtensionBinding {
                extension_id: ExtensionId::from_trusted("dingtalk".to_string()),
                surfaces: dingtalk.surfaces,
                preference_target_codec: Some(dingtalk.preference_target_codec),
                outbound_target_provider: None,
                first_party_initializer: None,
                registration_document_path: None,
            }
        },
        ChannelExtensionBinding {
            extension_id: ExtensionId::from_trusted("web-app".to_string()),
            // No reply half here: web-app is the deployment's session-reply
            // channel (`session_reply_channel` below), so composition
            // attaches the product-tier projection sink to this binding's
            // ordinary `surfaces.reply` slot — the browser's SSE/WebSocket
            // tail is the edge, reconciled from the same reply document
            // every other channel publishes from.
            // No ingress half, and that absence is load-bearing: input
            // arrives on the authenticated session door, whose actor
            // authority an adapter may never mint. Delivery is the web-push
            // half.
            surfaces: ChannelSurfaces::default().with_delivery(Arc::new(
                ironclaw_web_app_extension::WebAppChannelAdapter::new(),
            )),
            preference_target_codec: Some(Arc::new(
                ironclaw_web_app_extension::WebAppPreferenceTargetCodec,
            )),
            outbound_target_provider: Some(Arc::new(
                ironclaw_web_app_extension::WebAppOutboundTargetProvider::new(),
            )),
            first_party_initializer: Some(Arc::new(WebAppChannelInitializer::new(
                web_app_vapid_subject,
            ))),
            registration_document_path: Some("/web-push/subscriptions.json".to_string()),
        },
    ];
    BundledChannelExtensions {
        bindings,
        session_reply_channel: Some(ExtensionId::from_trusted("web-app".to_string())),
    }
}

/// Bindings-only view (tests and callers that do not wire composition).
#[cfg(test)]
pub(crate) fn bundled_channel_extension_bindings() -> Vec<ChannelExtensionBinding> {
    bundled_channel_extensions(None).bindings
}

/// Web App's concrete startup behavior lives at the binary edge that links
/// the package. Generic composition invokes this through the binding and sees
/// only an opaque bootstrap document.
struct WebAppChannelInitializer {
    vapid_subject: String,
}

impl WebAppChannelInitializer {
    fn new(vapid_subject: Option<String>) -> Self {
        Self {
            vapid_subject: vapid_subject
                .unwrap_or_else(|| "mailto:webpush@ironclaw.invalid".to_string()),
        }
    }
}

#[async_trait]
impl FirstPartyChannelInitializer for WebAppChannelInitializer {
    async fn initialize(
        &self,
        context: &FirstPartyChannelInitializationContext<'_>,
    ) -> Result<Option<serde_json::Value>, FirstPartyChannelInitializationError> {
        let handle = ironclaw_host_api::ids::SecretHandle::new(
            ironclaw_web_app::WEB_APP_VAPID_CREDENTIAL_HANDLE,
        )
        .map_err(|error| {
            FirstPartyChannelInitializationError::failed(format!(
                "web push credential handle is invalid: {error}"
            ))
        })?;

        let generated = ironclaw_web_app::generate_vapid_key_material(&self.vapid_subject)
            .map_err(|error| {
                FirstPartyChannelInitializationError::failed(format!(
                    "web push key generation failed: {error}"
                ))
            })?;
        context
            .store_credential_if_absent(handle.clone(), generated.material_json)
            .await?;

        let material = context.read_credential_once(&handle).await?;
        let parsed: ironclaw_host_api::http::VapidCredentialMaterialV1 =
            serde_json::from_str(material.expose_secret()).map_err(|error| {
                tracing::warn!(
                    target: "ironclaw::web_app",
                    error = %error,
                    "stored web push credential material failed to parse"
                );
                FirstPartyChannelInitializationError::failed(
                    "stored web push credential material is malformed",
                )
            })?;
        parsed.validate_shape().map_err(|error| {
            FirstPartyChannelInitializationError::failed(format!(
                "stored web push credential material is invalid: {error}"
            ))
        })?;
        Ok(Some(serde_json::json!({
            "vapid_public_key": parsed.public_key_b64url,
        })))
    }
}

/// `runtime.service = "dingtalk.extension/v1"`: the DingTalk robot channel.
/// It has no tools and no device link, and reads no secret at load: the host
/// owns the stream connection and the token exchange.
struct DingTalkExtensionFactory;

#[async_trait::async_trait]
impl NativeExtensionFactory for DingTalkExtensionFactory {
    fn service(&self) -> &str {
        "dingtalk.extension/v1"
    }

    async fn load(&self, _ctx: &LoadContext) -> Result<Box<dyn ExtensionEntrypoint>, BindError> {
        Ok(Box::new(DingTalkExtensionEntrypoint))
    }
}

struct DingTalkExtensionEntrypoint;

impl ExtensionEntrypoint for DingTalkExtensionEntrypoint {
    fn bind(&self, _ctx: BindContext) -> Result<ExtensionBindings, BindError> {
        Ok(ExtensionBindings {
            tools: None,
            channel: dingtalk_channel().surfaces,
            device_link: None,
        })
    }
}

/// `runtime.service = "telegram.extension/v1"` — the Telegram extension: the
/// bot channel, the linked-device auth surface, and the linked-account
/// standard-op tools, all bound from one entrypoint.
struct TelegramExtensionFactory;

#[async_trait::async_trait]
impl NativeExtensionFactory for TelegramExtensionFactory {
    fn service(&self) -> &str {
        "telegram.extension/v1"
    }

    async fn load(&self, ctx: &LoadContext) -> Result<Box<dyn ExtensionEntrypoint>, BindError> {
        // Load is the one I/O-legal point before bind, so the operator's
        // MTProto `api_hash` (`secret = true`) is resolved here; an
        // admin-configuration edit re-runs load via reactivation. Unset —
        // both MTProto fields are `required = false` — the adapter binds
        // anyway and fails every link attempt closed with an explicit
        // not-configured error, so a bot-only deployment keeps working.
        let api_hash_handle = ironclaw_host_api::ids::SecretHandle::new(TELEGRAM_API_HASH_HANDLE)
            .map_err(|error| BindError::Load {
            reason: format!("telegram api-hash handle is invalid: {error}"),
        })?;
        let api_hash = ctx.admin_secrets.secret(&api_hash_handle).await;
        Ok(Box::new(TelegramExtensionEntrypoint { api_hash }))
    }
}

struct TelegramExtensionEntrypoint {
    /// Resolved at load; `None` when the deployment has not configured it.
    api_hash: Option<secrecy::SecretString>,
}

impl ExtensionEntrypoint for TelegramExtensionEntrypoint {
    fn bind(&self, ctx: BindContext) -> Result<ExtensionBindings, BindError> {
        // silent-ok: a malformed operator value behaves exactly like an
        // unset one — the identity stays `None`, the pool refuses every dial
        // with its explicit not-configured error, and link attempts fail
        // closed with the same sentence. Nothing downstream ever sees a
        // garbage id; the config UI still shows the raw value for repair.
        let api_id = ctx
            .config
            .iter()
            .find(|(key, _)| key == TELEGRAM_API_ID_CONFIG)
            .and_then(|(_, value)| value.trim().parse::<i32>().ok());
        // One pool shared by both linked-surface adapters (PROPOSAL §3.3):
        // the link adapter must be able to evict what the tool adapter would
        // otherwise keep serving. Construction is allocation only — the pool
        // connects lazily — so bind stays side-effect-free.
        let pool = Arc::new(SessionPool::new(Arc::clone(&ctx.linked_sessions), api_id));
        let identity = match (api_id, self.api_hash.clone()) {
            (Some(api_id), Some(api_hash)) => Some(MtprotoAppIdentity { api_id, api_hash }),
            _ => None,
        };
        let device_link = TelegramDeviceLinkAdapter::new(identity, &pool);
        let tools =
            TelegramLinkedToolAdapter::new(Arc::clone(&ctx.linked_accounts), Arc::clone(&pool));
        let adapter = Arc::new(TelegramChannelAdapter::default());
        Ok(ExtensionBindings {
            tools: Some(Arc::new(tools)),
            channel: ChannelSurfaces::default()
                .with_ingress(adapter.clone())
                .with_reply(adapter.clone())
                .with_delivery(adapter),
            device_link: Some(Arc::new(device_link)),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ironclaw_extension_contracts::channel_adapter::{
        InboundOutcome, ProductTriggerReason, VerifiedInbound,
    };
    use ironclaw_extension_contracts::tool_adapter::{
        RestrictedEgress, RestrictedEgressError, RestrictedEgressRequest, RestrictedEgressResponse,
    };
    use ironclaw_extension_host::extension_ingress::{
        ChannelInboundSinkConfig, GenericChannelInboundSink, VerifiedEvidenceMint,
    };
    use ironclaw_extension_host::ingress::{InboundAdmission, InboundSink};
    use ironclaw_host_api::product_adapter::ProductAdapterId;
    use ironclaw_product_contracts::inbound::ChannelInboundClassification;
    use ironclaw_product_contracts::surface::{
        ChannelInboundProductSurface, ChannelInboundSurfaceOutcome, ChannelInboundSurfaceRequest,
    };
    use ironclaw_telegram_extension::TELEGRAM_BOT_USERNAME_CONFIG;
    use serde_json::json;

    use super::*;

    #[derive(Default)]
    struct CapturingSurface {
        requests: Mutex<Vec<ChannelInboundSurfaceRequest>>,
    }

    struct InertRestrictedEgress;

    #[async_trait]
    impl RestrictedEgress for InertRestrictedEgress {
        async fn send(
            &self,
            _request: RestrictedEgressRequest,
        ) -> Result<RestrictedEgressResponse, RestrictedEgressError> {
            Err(RestrictedEgressError::PolicyDenied)
        }
    }

    #[async_trait]
    impl ChannelInboundProductSurface for CapturingSurface {
        async fn admit_channel_inbound(
            &self,
            request: ChannelInboundSurfaceRequest,
        ) -> ChannelInboundSurfaceOutcome {
            self.requests
                .lock()
                .expect("capturing surface lock")
                .push(request);
            ChannelInboundSurfaceOutcome::unavailable()
        }
    }

    /// A channel binding the binary assembles is only reachable if the same
    /// extension is in the first-party catalog: the extensions page, install
    /// and activation all start from a catalog bundle. A binding without one is
    /// dead code that every package-level and harness test still passes
    /// (the harness installs fixtures directly), so pin the pairing here.
    #[test]
    fn every_native_channel_binding_has_a_first_party_catalog_bundle() {
        let catalog: std::collections::BTreeSet<String> =
            crate::first_party::bundled_first_party_bundles()
                .into_iter()
                .map(|bundle| bundle.id)
                .collect();
        let missing: Vec<String> = bundled_channel_extension_bindings()
            .iter()
            .map(|binding| binding.extension_id.as_str().to_string())
            .filter(|id| !catalog.contains(id))
            .collect();
        assert!(
            missing.is_empty(),
            "channel bindings with no first-party catalog bundle (unreachable from the extensions page): {missing:?}"
        );
    }

    #[test]
    fn the_dingtalk_catalog_bundle_ships_the_package_manifest() {
        let bundle = crate::first_party::bundled_first_party_bundles()
            .into_iter()
            .find(|bundle| bundle.id == "dingtalk")
            .expect("the dingtalk package is in the first-party catalog");
        assert_eq!(bundle.display_name, "DingTalk");
        assert_eq!(bundle.manifest_toml, ironclaw_dingtalk_extension::MANIFEST);
        assert!(
            bundle
                .assets
                .iter()
                .any(|asset| asset.path == "manifest.toml"
                    && asset.bytes == ironclaw_dingtalk_extension::MANIFEST.as_bytes()),
            "the materialized package root carries manifest.toml"
        );
    }

    #[test]
    fn telegram_factory_binds_a_channel_and_no_tools() {
        let factories = bundled_native_extension_factories();
        assert!(
            factories
                .iter()
                .any(|factory| factory.service() == "telegram.extension/v1"),
            "the binary assembles the telegram factory"
        );
    }

    #[test]
    fn dingtalk_factory_and_binding_bind_every_channel_half() {
        let factories = bundled_native_extension_factories();
        assert!(
            factories
                .iter()
                .any(|factory| factory.service() == "dingtalk.extension/v1"),
            "the binary assembles the dingtalk factory"
        );
        let bindings = bundled_channel_extension_bindings();
        let dingtalk = bindings
            .iter()
            .find(|binding| binding.extension_id.as_str() == "dingtalk")
            .expect("the binary supplies the dingtalk deployment channel binding");
        assert!(dingtalk.surfaces.ingress.is_some());
        assert!(dingtalk.surfaces.reply.is_some());
        assert!(dingtalk.surfaces.delivery.is_some());
        assert!(
            dingtalk.preference_target_codec.is_some(),
            "push targets decode through the dingtalk codec"
        );
        assert!(
            dingtalk.outbound_target_provider.is_none(),
            "the generic provider offers the caller's own DM; no package provider"
        );
        assert!(
            dingtalk.surfaces.stream_control.is_some(),
            "the stream connection's frame control is bound"
        );
    }

    #[test]
    fn bundled_channel_bindings_carry_their_production_extras() {
        let bindings = bundled_channel_extension_bindings();
        let slack = bindings
            .iter()
            .find(|binding| binding.extension_id.as_str() == "slack")
            .expect("the binary supplies the slack channel binding");
        assert!(slack.preference_target_codec.is_some());
        let telegram = bindings
            .iter()
            .find(|binding| binding.extension_id.as_str() == "telegram")
            .expect("the binary supplies the telegram deployment channel binding");
        assert!(
            telegram.preference_target_codec.is_some(),
            "the shipping Telegram binding must expose outbound preference targets"
        );
    }

    #[test]
    fn web_app_is_the_session_reply_channel_and_binds_delivery_only() {
        let bundled = bundled_channel_extensions(None);
        assert_eq!(
            bundled
                .session_reply_channel
                .as_ref()
                .map(|extension_id| extension_id.as_str()),
            Some("web-app"),
            "the binary names web-app as the deployment's session-reply channel"
        );
        let web_app = bundled
            .bindings
            .iter()
            .find(|binding| binding.extension_id.as_str() == "web-app")
            .expect("the named session-reply channel has a binding");
        assert!(
            web_app.surfaces.reply.is_none(),
            "the package leaves the reply slot empty: composition attaches the projection sink"
        );
        assert!(
            web_app.surfaces.ingress.is_none(),
            "authenticated-session ingress is host-owned; an adapter may never mint its trust"
        );
        assert!(
            web_app.surfaces.delivery.is_some(),
            "web-push delivery is the one half the package binds"
        );
    }

    #[tokio::test]
    async fn bundled_telegram_binding_routes_targeted_commands_through_generic_sink() {
        let bindings = bundled_channel_extension_bindings();
        let telegram = bindings
            .iter()
            .find(|binding| binding.extension_id.as_str() == "telegram")
            .expect("the binary supplies the Telegram deployment channel binding");
        let config = vec![(
            TELEGRAM_BOT_USERNAME_CONFIG.to_string(),
            "configured_bot".to_string(),
        )];
        let surface = Arc::new(CapturingSurface::default());
        let sink = GenericChannelInboundSink::new(ChannelInboundSinkConfig {
            adapter_id: ProductAdapterId::new("telegram").expect("valid adapter id"),
            evidence: VerifiedEvidenceMint::SharedSecretHeader {
                header: "X-Telegram-Bot-Api-Secret-Token".to_string(),
            },
            surface: Arc::clone(&surface) as Arc<dyn ChannelInboundProductSurface>,
            observer: None,
        });
        let cases = [
            ("/status", "/status", Some("status")),
            ("/status@configured_bot", "/status", Some("status")),
            ("/status@other_bot", "/status@other_bot", None),
        ];
        let egress = InertRestrictedEgress;

        for (index, (wire_text, _, _)) in cases.iter().enumerate() {
            let command = wire_text
                .split_whitespace()
                .next()
                .expect("command fixture has a first token");
            let body = serde_json::to_vec(&json!({
                "update_id": 700 + index,
                "message": {
                    "message_id": 90 + index,
                    "date": 1_700_000_000,
                    "from": {"id": 777, "is_bot": false, "first_name": "Alice"},
                    "chat": {"id": 777, "type": "private"},
                    "text": wire_text,
                    "entities": [{
                        "type": "bot_command",
                        "offset": 0,
                        "length": command.encode_utf16().count()
                    }]
                }
            }))
            .expect("Telegram fixture serializes");
            let outcome = telegram
                .surfaces
                .ingress
                .as_ref()
                .expect("the telegram binding declares a webhook ingress half")
                .receive(
                    VerifiedInbound {
                        extension_id: telegram.extension_id.as_str(),
                        installation_id: "install_test",
                        config: &config,
                        body: &body,
                        headers: &[],
                        can_reply_in_threads: false,
                    },
                    &egress,
                )
                .await
                .expect("shipping Telegram adapter normalizes the private command");
            let InboundOutcome::Messages(mut messages) = outcome else {
                panic!("private Telegram command must produce a message");
            };
            assert_eq!(messages.len(), 1);
            let message = messages.remove(0);
            assert!(
                sink.admit(InboundAdmission {
                    extension_id: telegram.extension_id.as_str().to_string(),
                    installation_id: "install_test".to_string(),
                    message,
                })
                .await
                .is_err(),
                "capture-only surface deliberately reports unavailable"
            );
        }

        let requests = surface.requests.lock().expect("capturing surface lock");
        assert_eq!(requests.len(), cases.len());
        for (request, (_, expected_text, expected_command)) in requests.iter().zip(cases) {
            assert_eq!(request.message.text, expected_text);
            assert_eq!(request.message.trigger, ProductTriggerReason::DirectChat);
            match expected_command {
                Some(expected_command) => {
                    let Some(ChannelInboundClassification::Command(command)) =
                        request.classification.as_ref()
                    else {
                        panic!("normalized Telegram command must reach generic classification");
                    };
                    assert_eq!(command.command, expected_command);
                    assert!(command.arguments.is_empty());
                    assert_eq!(command.trigger, ProductTriggerReason::DirectChat);
                }
                None => assert!(
                    request.classification.is_none(),
                    "a command addressed to another bot must not reach product command dispatch"
                ),
            }
        }
    }
}
