//! Host-path harness: the REAL `GenericChannelHostAssembly` builds the stream
//! channel's inbound graph (sealed `AuthenticatedStream` evidence, registry
//! registration, drain) and the REAL supervisor feeds it, with the product
//! admission surface replaced by a recorder at the `ChannelInboundProductSurface`
//! seam. Configuration changes go through the real `ChannelConfigService`,
//! whose reactivation is `ExtensionHost::deactivate` + `activate`.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ironclaw_extension_contracts::state::InstallationState;
use ironclaw_extension_host::channel_host::{
    ChannelHostIdentity, GenericChannelHostAssembly, GenericChannelHostDeps,
};
use ironclaw_extension_host::egress::ChannelEgressTransport;
use ironclaw_extension_host::extension_ingress::{ExtensionIngressParts, build_extension_ingress};
use ironclaw_extension_host::stream_supervisor::{
    StreamAuditSink, StreamSupervisor, StreamSupervisorConfig, StreamSupervisorDeps,
};
use ironclaw_extension_host::{
    AdminConfigurationService, ChannelConfigReactivation, ChannelConfigReactivationError,
    ChannelConfigService, DeploymentChannelRegistry, ExtensionHost, ExtensionHostDeps,
    FilesystemAdminConfigurationStore, FilesystemInboundBatchStore, FilesystemReplyContextStore,
    InstallationRecord, InstallationRecordStore, RehydratedInstallationRecordStore,
    product_extension_host_api_contract_registry,
};
use ironclaw_extension_registry::{
    ExtensionInstallation, ExtensionInstallationId, ExtensionInstallationStorePort as _,
    ExtensionManifestRecord, ExtensionManifestRef, InstallationOwner, ManifestSource,
};
use ironclaw_filesystem::{InMemoryBackend, RootFilesystem, ScopedFilesystem};
use ironclaw_host_api::ids::{AgentId, ExtensionId, InvocationId, ProjectId, TenantId, UserId};
use ironclaw_host_api::mount::{MountGrant, MountPermissions, MountView};
use ironclaw_host_api::path::{MountAlias, VirtualPath};
use ironclaw_host_api::resource::ResourceScope;
use ironclaw_host_api::turn::{AcceptedMessageRef, TurnRunId};
use ironclaw_network::{LoopbackWebSocketTransport, PolicyWebSocketConnector, WebSocketConnector};
use ironclaw_product_contracts::admin_users::{
    AdminCreateUserFields, AdminCreatedUser, AdminUserError, AdminUserRecord, AdminUserRole,
    AdminUserSecretMeta, AdminUserService, AdminUserStatus,
};
use ironclaw_product_contracts::binding::{
    ProductBindingResolver, ResolveBindingRequest, ResolvedBinding,
};
use ironclaw_product_contracts::channel_workflow::{
    ChannelWorkflowFactory, ChannelWorkflowGraph, ChannelWorkflowRequest,
};
use ironclaw_product_contracts::error::ProductOperationFailure;
use ironclaw_product_contracts::inbound::{
    ParsedProductInbound, ProductInboundAck, ProductInboundEnvelope, ProductInboundPayload,
    UserMessagePayload,
};
use ironclaw_product_contracts::surface::{
    ChannelInboundProductSurface, ChannelInboundSurfaceAdmission, ChannelInboundSurfaceOutcome,
    ChannelInboundSurfaceRequest,
};
use ironclaw_secrets::{SecretStore, SecretStorePort};
use secrecy::SecretString;

use super::{
    ConnectEgress, EXTENSION_ID, FixedLoader, Gateway, INSTALLATION_ID, Log, PublicResolver,
    RecordingAudit, manifest_with,
};

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Records what reaches product admission and answers `Accepted`.
pub struct RecordingSurface {
    pub log: Log,
    /// `Debug` of each request's trusted context (adapter, installation, and
    /// the sealed claim's requirement).
    pub contexts: Mutex<Vec<String>>,
    pub installations: Mutex<Vec<String>>,
}

#[async_trait]
impl ChannelInboundProductSurface for RecordingSurface {
    async fn admit_channel_inbound(
        &self,
        request: ChannelInboundSurfaceRequest,
    ) -> ChannelInboundSurfaceOutcome {
        lock(&self.contexts).push(format!("{:?}", request.context));
        lock(&self.log).push(format!("surface:{}", request.message.event_id.as_str()));
        let ack = ProductInboundAck::Accepted {
            accepted_message_ref: AcceptedMessageRef::new("msg:stream-test")
                .expect("accepted message ref"),
            submitted_run_id: TurnRunId::new(),
            submission: None,
        };
        let envelope = ProductInboundEnvelope::from_trusted_parse(
            request.context,
            ParsedProductInbound::new(
                request.message.event_id,
                request.message.actor,
                request.message.conversation,
                ProductInboundPayload::UserMessage(
                    UserMessagePayload::new(
                        request.message.text,
                        Vec::new(),
                        request.message.trigger,
                    )
                    .expect("user message payload"),
                ),
            )
            .expect("parsed inbound"),
        )
        .expect("trusted envelope");
        lock(&self.installations).push(envelope.installation_id().as_str().to_string());
        ChannelInboundSurfaceOutcome::Admitted(Box::new(ChannelInboundSurfaceAdmission {
            envelope,
            ack,
        }))
    }
}

struct StubBinding;

#[async_trait]
impl ProductBindingResolver for StubBinding {
    async fn resolve_binding(
        &self,
        _request: ResolveBindingRequest,
    ) -> Result<ResolvedBinding, ProductOperationFailure> {
        Err(ProductOperationFailure::BindingResolutionFailed {
            reason: "stream host-path test resolves no bindings".to_string(),
        })
    }

    async fn lookup_binding(
        &self,
        _request: ResolveBindingRequest,
    ) -> Result<ResolvedBinding, ProductOperationFailure> {
        Err(ProductOperationFailure::BindingResolutionFailed {
            reason: "stream host-path test resolves no bindings".to_string(),
        })
    }
}

struct StubWorkflowFactory {
    surface: Arc<RecordingSurface>,
}

#[async_trait]
impl ChannelWorkflowFactory for StubWorkflowFactory {
    async fn build_channel_workflow(
        &self,
        _request: ChannelWorkflowRequest,
    ) -> Result<ChannelWorkflowGraph, String> {
        Ok(ChannelWorkflowGraph {
            surface: Arc::clone(&self.surface) as Arc<dyn ChannelInboundProductSurface>,
            binding: Arc::new(StubBinding),
            observer: None,
        })
    }
}

struct UnavailableAdminUsers;

#[async_trait]
impl AdminUserService for UnavailableAdminUsers {
    async fn list_users(
        &self,
        _t: &TenantId,
        _s: Option<AdminUserStatus>,
        _a: Option<&UserId>,
        _l: usize,
    ) -> Result<Vec<AdminUserRecord>, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn get_user(
        &self,
        _t: &TenantId,
        _u: &UserId,
    ) -> Result<Option<AdminUserRecord>, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn create_user(
        &self,
        _t: &TenantId,
        _a: &UserId,
        _f: AdminCreateUserFields,
    ) -> Result<AdminCreatedUser, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn update_profile(
        &self,
        _t: &TenantId,
        _u: &UserId,
        _d: Option<String>,
        _m: Option<BTreeMap<String, String>>,
    ) -> Result<AdminUserRecord, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn set_status(
        &self,
        _t: &TenantId,
        _u: &UserId,
        _s: AdminUserStatus,
    ) -> Result<AdminUserRecord, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn set_role(
        &self,
        _t: &TenantId,
        _u: &UserId,
        _r: AdminUserRole,
    ) -> Result<AdminUserRecord, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn delete_user(&self, _t: &TenantId, _u: &UserId) -> Result<(), AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn count_active_admins(&self, _t: &TenantId) -> Result<usize, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn list_secrets(
        &self,
        _t: &TenantId,
        _u: &UserId,
    ) -> Result<Vec<AdminUserSecretMeta>, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn put_secret(
        &self,
        _t: &TenantId,
        _u: &UserId,
        _h: ironclaw_host_api::ids::SecretHandle,
        _m: SecretString,
    ) -> Result<AdminUserSecretMeta, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
    async fn delete_secret(
        &self,
        _t: &TenantId,
        _u: &UserId,
        _h: ironclaw_host_api::ids::SecretHandle,
    ) -> Result<bool, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
}

/// The configure surface's reactivation: the same deactivate -> activate
/// cycle `ExtensionLifecycleManager` runs, directly on the host.
struct HostReactivation {
    host: Arc<ExtensionHost>,
}

#[async_trait]
impl ChannelConfigReactivation for HostReactivation {
    async fn reactivate_if_active(
        &self,
        extension_id: &ExtensionId,
    ) -> Result<(), ChannelConfigReactivationError> {
        // A no-op unless the extension is currently active, like production.
        if self
            .host
            .snapshot_watch()
            .current()
            .extension(extension_id.as_str())
            .is_none()
        {
            return Ok(());
        }
        self.host
            .deactivate(extension_id.as_str())
            .await
            .map_err(|error| ChannelConfigReactivationError::new(error.to_string()))?;
        self.host
            .activate(extension_id.as_str())
            .await
            .map_err(|error| ChannelConfigReactivationError::new(error.to_string()))
    }
}

pub struct AssemblyHarness {
    pub host: Arc<ExtensionHost>,
    pub gateway: Gateway,
    pub egress: Arc<ConnectEgress>,
    pub audit: Arc<RecordingAudit>,
    pub surface: Arc<RecordingSurface>,
    pub log: Log,
    pub channel_config: Arc<ChannelConfigService>,
    pub assembly: Arc<GenericChannelHostAssembly>,
    pub ingress: ExtensionIngressParts,
    pub supervisor: Arc<StreamSupervisor>,
}

const TENANT: &str = "tenant-stream";
const USER: &str = "user-stream";

fn scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new(TENANT).expect("tenant"),
        user_id: UserId::new(USER).expect("user"),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

impl AssemblyHarness {
    pub async fn start(config: StreamSupervisorConfig) -> Self {
        let log: Log = Arc::default();
        let gateway = Gateway::start(Arc::clone(&log)).await;
        let egress = ConnectEgress::new();
        let audit = Arc::new(RecordingAudit::default());
        let surface = Arc::new(RecordingSurface {
            log: Arc::clone(&log),
            contexts: Mutex::default(),
            installations: Mutex::default(),
        });
        let store = Arc::new(RehydratedInstallationRecordStore::default());
        let host = Arc::new(
            ExtensionHost::new(ExtensionHostDeps {
                store: Arc::clone(&store) as Arc<dyn InstallationRecordStore>,
                loader: Arc::new(FixedLoader::default()),
                drain: Arc::new(ironclaw_extension_host::test_support::RecordingDrain::default()),
                egress: Arc::new(ironclaw_extension_host::test_support::FakeEgressFactory),
                reserved_capability_ids: Default::default(),
                reserved_ingress_routes: Default::default(),
                hook_deadline: Duration::from_secs(5),
                linked_sessions: ironclaw_extension_host::LinkedSessionStore::unavailable(),
                linked_accounts: Arc::new(
                    ironclaw_extension_host::UnavailableLinkedAccountResolution,
                ),
                admin_secrets: None,
            })
            .await,
        );
        let channel_config = configured_channel_config(Arc::clone(&host)).await;
        let deployment_channels = Arc::new(DeploymentChannelRegistry::default());
        let ingress = build_extension_ingress(
            host.snapshot_watch(),
            Arc::clone(&deployment_channels),
            Arc::new(FilesystemReplyContextStore::new(
                Arc::new(InMemoryBackend::new()),
                TenantId::new(TENANT).expect("tenant"),
                UserId::new(USER).expect("user"),
            )),
            Arc::new(
                FilesystemInboundBatchStore::new(
                    Arc::new(InMemoryBackend::new()),
                    TenantId::new(TENANT).expect("tenant"),
                    UserId::new(USER).expect("user"),
                )
                .expect("batch store"),
            ),
            Some(Arc::clone(&egress) as Arc<dyn ChannelEgressTransport>),
        );
        let assembly = GenericChannelHostAssembly::start(GenericChannelHostDeps {
            watch: host.snapshot_watch(),
            deployment_channels: Arc::clone(&deployment_channels),
            registry: Arc::clone(&ingress.registry),
            channel_config: Arc::clone(&channel_config),
            channel_workflow: Arc::new(StubWorkflowFactory {
                surface: Arc::clone(&surface),
            }),
            identity: ChannelHostIdentity {
                tenant_id: TenantId::new(TENANT).expect("tenant"),
                agent_id: AgentId::new("agent-stream").expect("agent"),
                project_id: Some(ProjectId::new("project-stream").expect("project")),
                operator_user_id: UserId::new(USER).expect("user"),
            },
            identity_lookup: None,
            dm_targets: None,
            channel_pairing: None,
            admin_users: Arc::new(UnavailableAdminUsers),
            connect_link_base_url: None,
        });
        let connector: Arc<dyn WebSocketConnector> =
            Arc::new(PolicyWebSocketConnector::new_with_resolver(
                LoopbackWebSocketTransport::new(gateway.addr),
                PublicResolver,
            ));
        let supervisor = StreamSupervisor::start(
            StreamSupervisorDeps {
                watch: host.snapshot_watch(),
                deployment_channels,
                admission: ingress.router.stream_admission(),
                connector,
                scope: scope(),
                audit: Arc::clone(&audit) as Arc<dyn StreamAuditSink>,
            },
            config,
        );
        Self {
            host,
            gateway,
            egress,
            audit,
            surface,
            log,
            channel_config,
            assembly,
            ingress,
            supervisor,
        }
    }

    /// Install through the host and activate (the lifecycle's publication).
    pub async fn activate(&self) {
        let record = manifest_record();
        self.host
            .install(InstallationRecord {
                extension_id: EXTENSION_ID.to_string(),
                installation_id: INSTALLATION_ID.to_string(),
                state: InstallationState::Installed,
                resolved: Arc::new(record.resolved().clone()),
                config: Vec::new(),
                last_error: None,
            })
            .await
            .expect("install");
        self.host.activate(EXTENSION_ID).await.expect("activate");
    }
}

fn manifest_record() -> ExtensionManifestRecord {
    ExtensionManifestRecord::from_toml(
        manifest_with(&[]),
        ManifestSource::HostBundled,
        &ironclaw_host_api::host_port::default_host_port_catalog().expect("catalog"),
        None,
        &product_extension_host_api_contract_registry().expect("contracts"),
        None,
    )
    .expect("acme stream manifest resolves")
}

/// `[admin_configuration]` configured through the production configure
/// service over the acme stream manifest.
async fn configured_channel_config(host: Arc<ExtensionHost>) -> Arc<ChannelConfigService> {
    let installation_store =
        Arc::new(ironclaw_extension_host::filesystem_installation_store_for_test().await);
    let record = manifest_record();
    let admin_configuration = record.resolved().admin_configuration.clone();
    let extension_id = ExtensionId::new(EXTENSION_ID).expect("extension id");
    installation_store
        .upsert_manifest_and_installation(
            record,
            ExtensionInstallation::new(
                ExtensionInstallationId::new(INSTALLATION_ID.to_string()).expect("installation id"),
                extension_id.clone(),
                ExtensionManifestRef::new(extension_id.clone(), None),
                Vec::new(),
                chrono::Utc::now(),
                InstallationOwner::Tenant,
            )
            .expect("installation"),
        )
        .await
        .expect("persist install");
    let scope = scope();
    let secrets = Arc::new(SecretStore::ephemeral());
    let admin_filesystem: Arc<dyn RootFilesystem> = Arc::new(InMemoryBackend::new());
    let admin = Arc::new(
        AdminConfigurationService::new(
            FilesystemAdminConfigurationStore::new(Arc::new(ScopedFilesystem::new(
                admin_filesystem,
                |_scope| {
                    MountView::new(vec![MountGrant::new(
                        MountAlias::new("/extension-admin-configuration").expect("alias"),
                        VirtualPath::new(format!("/tenants/{TENANT}/shared/admin-configuration"))
                            .expect("path"),
                        MountPermissions::read_write_list_delete(),
                    )])
                },
            ))),
            Arc::clone(&secrets) as Arc<dyn SecretStorePort>,
            admin_configuration,
        )
        .expect("admin configuration service"),
    );
    let channel_config = Arc::new(
        ChannelConfigService::new(
            installation_store,
            Arc::clone(&secrets) as Arc<dyn SecretStorePort>,
            scope.clone(),
            Arc::new(HostReactivation { host }),
        )
        .with_admin_configuration(admin, scope),
    );
    channel_config
        .save(
            &extension_id,
            vec![
                ("acme_client_id".to_string(), "client-1".to_string()),
                ("acme_client_secret".to_string(), "secret-1".to_string()),
            ],
        )
        .await
        .expect("save channel config");
    channel_config
}
