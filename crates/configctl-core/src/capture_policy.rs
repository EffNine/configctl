//! v1.1 capture policy: aggressive by default, explicit always.
//!
//! Discovery is hardcore; capture decides per resource whether to
//! `capture`, `reference`, `observe`, or `exclude` — and every non-capture
//! decision carries a required reason. The execution engine (plan/apply)
//! consumes these classes through [`crate::classify::PlanActionClass`].

use crate::classify::{CaptureAction, EnvClass, PlanActionClass, ResourceClass};
use std::collections::BTreeMap;

/// One explicit capture verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureDecision {
    pub action: CaptureAction,
    pub reason: String,
}

impl CaptureDecision {
    pub fn capture(reason: impl Into<String>) -> Self {
        Self {
            action: CaptureAction::Capture,
            reason: reason.into(),
        }
    }

    pub fn reference(reason: impl Into<String>) -> Self {
        Self {
            action: CaptureAction::Reference,
            reason: reason.into(),
        }
    }

    pub fn observe(reason: impl Into<String>) -> Self {
        Self {
            action: CaptureAction::Observe,
            reason: reason.into(),
        }
    }

    pub fn exclude(reason: impl Into<String>) -> Self {
        Self {
            action: CaptureAction::Exclude,
            reason: reason.into(),
        }
    }
}

/// Decide a home-dotfile payload from its discovery classification.
pub fn decide_home_file(class: ResourceClass) -> CaptureDecision {
    match class {
        ResourceClass::Portable | ResourceClass::Reproducible => {
            CaptureDecision::capture("portable configuration; safe to reproduce")
        }
        ResourceClass::Secret => {
            CaptureDecision::reference("secret-bearing file; value never stored, reference only")
        }
        ResourceClass::Credential => {
            CaptureDecision::observe("credential-adjacent metadata observed, material not captured")
        }
        ResourceClass::Generated | ResourceClass::Cache => {
            CaptureDecision::exclude("generated/cache content excluded from reproduction")
        }
        ResourceClass::MachineSpecific => {
            CaptureDecision::observe("machine-specific content observed, not reproduced")
        }
        ResourceClass::Privileged => {
            CaptureDecision::observe("privileged content observed, not reproduced without privilege")
        }
        ResourceClass::Dependency | ResourceClass::Unsupported => {
            CaptureDecision::observe("dependency/unsupported content observed as metadata")
        }
        ResourceClass::Unknown => {
            CaptureDecision::observe("unclassified content preserved as observed metadata")
        }
    }
}

/// Decide a package name entry (names only — versions live in the lock).
pub fn decide_package(manager: &str, explicit: Option<bool>) -> CaptureDecision {
    match manager {
        "apt" => {
            if explicit.unwrap_or(false) {
                CaptureDecision::capture("explicitly requested apt package")
            } else {
                CaptureDecision::observe("apt package recorded; apply selects via tooling policy")
            }
        }
        _ => CaptureDecision::capture("package name captured with manager provenance"),
    }
}

/// Decide a systemd unit for profile emission.
pub fn decide_service(user_scope: bool) -> (CaptureDecision, PlanActionClass) {
    if user_scope {
        (
            CaptureDecision::capture("user unit reproduced via systemctl --user"),
            PlanActionClass::SafeReproduce,
        )
    } else {
        (
            CaptureDecision::observe("system unit observed; reproduction requires privilege"),
            PlanActionClass::Privileged,
        )
    }
}

/// Decide a global environment variable for profile emission.
pub fn decide_global_env(class: EnvClass) -> CaptureDecision {
    match class {
        EnvClass::Secret => CaptureDecision::reference("secret value never stored; backend reference only"),
        EnvClass::PublicConfig => CaptureDecision::capture("public configuration literal"),
        EnvClass::Path => CaptureDecision::observe("PATH-like variable mapped (entries/order recorded at scan); value not reproduced"),
        EnvClass::MachineSpecific => CaptureDecision::observe("machine-specific variable observed, not reproduced"),
        EnvClass::Runtime => CaptureDecision::exclude("runtime-ephemeral variable excluded"),
        EnvClass::Unknown => CaptureDecision::observe("unknown variable mapped by name only"),
    }
}

/// Decide mount / hardware / executable observations (always metadata).
pub fn decide_mount(remote: bool, pseudo: bool) -> CaptureDecision {
    if pseudo {
        CaptureDecision::observe("pseudo-filesystem recorded; never traversed or reproduced")
    } else if remote {
        CaptureDecision::observe("network mount recorded; recursive scan requires explicit opt-in")
    } else {
        CaptureDecision::observe("local mount recorded as reproduction context")
    }
}

/// Aggregate decisions into `action → count` for summaries.
pub fn summarize(decisions: &[CaptureDecision]) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for d in decisions {
        let key = match d.action {
            CaptureAction::Capture => "capture",
            CaptureAction::Reference => "reference",
            CaptureAction::Observe => "observe",
            CaptureAction::Exclude => "exclude",
        };
        *m.entry(key.to_string()).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn every_resource_class_has_a_decision_with_reason() {
        let classes = [
            ResourceClass::Portable,
            ResourceClass::Reproducible,
            ResourceClass::MachineSpecific,
            ResourceClass::Generated,
            ResourceClass::Cache,
            ResourceClass::Dependency,
            ResourceClass::Secret,
            ResourceClass::Credential,
            ResourceClass::Privileged,
            ResourceClass::Unsupported,
            ResourceClass::Unknown,
        ];
        for c in classes {
            let d = decide_home_file(c);
            assert!(!d.reason.is_empty(), "{c:?}");
        }
        // Secrets are never captured.
        assert_eq!(decide_home_file(ResourceClass::Secret).action, CaptureAction::Reference);
        // Unknown is preserved, not dropped.
        assert_eq!(decide_home_file(ResourceClass::Unknown).action, CaptureAction::Observe);
    }

    #[test]
    fn system_services_are_privileged_not_safe() {
        let (_, class) = decide_service(false);
        assert_eq!(class, PlanActionClass::Privileged);
        let (_, class) = decide_service(true);
        assert_eq!(class, PlanActionClass::SafeReproduce);
    }
}
