//! Installation incarnations: which installations exist, and which life of
//! each one this is.
//!
//! The host mints a number when an installation record first appears and
//! drops it when the record is deleted. Re-installing an existing record
//! keeps its number; installing again after a removal yields a strictly
//! larger one. A watcher that only sees the final state of a coalesced
//! remove-then-reinstall can therefore still tell the two installations apart.
//! Only extension ids and counters live here.

use std::collections::BTreeMap;

/// Immutable snapshot of the live installation incarnations, by extension id.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InstallationIncarnations {
    by_extension: BTreeMap<String, u64>,
}

impl InstallationIncarnations {
    /// The incarnation of `extension_id`'s installation, when one exists.
    pub fn get(&self, extension_id: &str) -> Option<u64> {
        self.by_extension.get(extension_id).copied()
    }

    /// Record that `extension_id` is installed. Keeps the existing number when
    /// there is one; otherwise takes `*next` and advances it. Returns whether
    /// the set changed.
    pub(crate) fn ensure(&mut self, extension_id: &str, next: &mut u64) -> bool {
        if self.by_extension.contains_key(extension_id) {
            return false;
        }
        *next = next.saturating_add(1);
        self.by_extension.insert(extension_id.to_string(), *next);
        true
    }

    /// Forget `extension_id`'s installation. Returns whether it was present.
    pub(crate) fn clear(&mut self, extension_id: &str) -> bool {
        self.by_extension.remove(extension_id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_install_mints_and_a_repeat_keeps_the_number() {
        let mut set = InstallationIncarnations::default();
        let mut next = 0;
        assert_eq!(set.get("a"), None);
        assert!(set.ensure("a", &mut next));
        let first = set.get("a");
        assert!(first.is_some());
        assert!(!set.ensure("a", &mut next));
        assert_eq!(set.get("a"), first);
    }

    #[test]
    fn clear_forgets_and_a_later_install_is_strictly_larger() {
        let mut set = InstallationIncarnations::default();
        let mut next = 0;
        set.ensure("a", &mut next);
        let first = set.get("a").unwrap_or_default();
        assert!(set.clear("a"));
        assert_eq!(set.get("a"), None);
        assert!(!set.clear("a"));
        set.ensure("a", &mut next);
        assert!(set.get("a").unwrap_or_default() > first);
    }
}
