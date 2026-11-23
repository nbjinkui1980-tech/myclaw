//! Configuration-change signal for stream connections.
//!
//! A deployment-bound stream connection follows the installation record, so
//! republishing the active snapshot (deactivate, re-activate) never replaces
//! it. When an administrator saves or changes the channel's configuration, the
//! host bumps a per-extension generation here and the supervisor restarts that
//! extension's deployment-sourced connection, once, which re-reads the stored
//! values. This signal is the only restart trigger for a deployment source
//! besides removing and re-installing the installation. Only extension ids and counters pass through
//! this type; it never sees a configuration value.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_host_api::ids::ExtensionId;
use tokio::sync::watch;

use crate::channel_config::{ChannelConfigReactivation, ChannelConfigReactivationError};

/// Per-extension counter of saved configuration changes.
#[derive(Debug)]
pub struct StreamConfigurationChanges {
    generations: watch::Sender<HashMap<String, u64>>,
}

impl Default for StreamConfigurationChanges {
    fn default() -> Self {
        Self {
            generations: watch::channel(HashMap::new()).0,
        }
    }
}

impl StreamConfigurationChanges {
    /// Record that `extension_id`'s configuration changed.
    pub fn notify(&self, extension_id: &str) {
        self.generations.send_modify(|generations| {
            let generation = generations.entry(extension_id.to_string()).or_insert(0);
            *generation = generation.saturating_add(1);
        });
    }

    pub(crate) fn generation(&self, extension_id: &str) -> u64 {
        self.generations
            .borrow()
            .get(extension_id)
            .copied()
            .unwrap_or(0)
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<HashMap<String, u64>> {
        self.generations.subscribe()
    }
}

/// Decorates the host's re-activation port: after the inner re-activation
/// runs, the extension's configuration generation advances so a deployment
/// stream connection restarts. The re-activation itself leaves a deployment
/// connection alone, so this is its one restart. The notification is
/// unconditional: the configuration is already persisted, and a connection
/// stopped for missing credentials should retry with the new values even when
/// re-activation reports an error.
pub struct StreamRestartingReactivation {
    inner: Arc<dyn ChannelConfigReactivation>,
    changes: Arc<StreamConfigurationChanges>,
}

impl StreamRestartingReactivation {
    pub fn new(
        inner: Arc<dyn ChannelConfigReactivation>,
        changes: Arc<StreamConfigurationChanges>,
    ) -> Self {
        Self { inner, changes }
    }
}

#[async_trait]
impl ChannelConfigReactivation for StreamRestartingReactivation {
    async fn reactivate_if_active(
        &self,
        extension_id: &ExtensionId,
    ) -> Result<(), ChannelConfigReactivationError> {
        let result = self.inner.reactivate_if_active(extension_id).await;
        self.changes.notify(extension_id.as_str());
        result
    }
}
