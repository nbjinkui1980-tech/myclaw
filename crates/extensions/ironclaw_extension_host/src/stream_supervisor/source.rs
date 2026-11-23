//! What the supervisor connects for: one installation's declared stream.
use std::sync::Arc;

use ironclaw_extension_contracts::channel::ChannelStreamDescriptor;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelIngress, ChannelStreamControl, ChannelSurfaces,
};
use ironclaw_extension_registry::ResolvedExtensionManifest;

use crate::active::ActiveExtension;
use crate::deployment_channels::DeploymentChannelBinding;

/// Where a stream channel's bindings came from. An active source is
/// identified by its `Arc`, so a republished (re-activated) extension is a
/// different source and its connection restarts. A deployment source is
/// identified by its binding and the installation incarnation: activation
/// changes (deactivate, re-activate) leave it alone, removing the
/// installation and installing again is a different incarnation and restarts
/// it, and an administrator configuration change restarts it through the
/// configuration-change signal.
#[derive(Clone)]
pub(super) enum StreamSource {
    Deployment {
        binding: Arc<DeploymentChannelBinding>,
        incarnation: u64,
    },
    Active(Arc<ActiveExtension>),
}

impl StreamSource {
    pub fn extension_id(&self) -> &str {
        match self {
            Self::Deployment { binding, .. } => &binding.extension_id,
            Self::Active(active) => &active.extension_id,
        }
    }

    /// The installation that owns the connection. A deployment channel has no
    /// user installation; its host-owned identity is the extension id, the
    /// same convention the webhook router and channel host use.
    pub fn installation_id(&self) -> &str {
        match self {
            Self::Deployment { binding, .. } => &binding.extension_id,
            Self::Active(active) => &active.installation_id,
        }
    }

    pub fn resolved(&self) -> &Arc<ResolvedExtensionManifest> {
        match self {
            Self::Deployment { binding, .. } => &binding.resolved,
            Self::Active(active) => &active.resolved,
        }
    }

    fn surfaces(&self) -> &ChannelSurfaces {
        match self {
            Self::Deployment { binding, .. } => &binding.surfaces,
            Self::Active(active) => &active.channel,
        }
    }

    /// Matches the binding-fingerprint kinds the webhook router uses.
    pub fn binding_kind(&self) -> &'static str {
        match self {
            Self::Deployment { .. } => "deployment",
            Self::Active(_) => "active",
        }
    }

    pub fn is_deployment(&self) -> bool {
        matches!(self, Self::Deployment { .. })
    }

    pub fn same_source(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Deployment {
                    binding: left,
                    incarnation: left_incarnation,
                },
                Self::Deployment {
                    binding: right,
                    incarnation: right_incarnation,
                },
            ) => Arc::ptr_eq(left, right) && left_incarnation == right_incarnation,
            (Self::Active(left), Self::Active(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    pub fn stream(&self) -> Option<&ChannelStreamDescriptor> {
        self.resolved().channel.as_ref()?.ingress.as_ref()?.stream()
    }

    pub fn ingress(&self) -> Option<&Arc<dyn ChannelIngress>> {
        self.surfaces().ingress.as_ref()
    }

    pub fn control(&self) -> Option<&Arc<dyn ChannelStreamControl>> {
        self.surfaces().stream_control.as_ref()
    }
}
