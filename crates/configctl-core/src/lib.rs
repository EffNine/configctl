//! configctl-core: domain types for discovery + declarative capture.
//!
//! This crate contains the redaction subsystem, the bounded `.env` parser,
//! the `CommandRunner` abstraction, and the P2 profile/capture model. It
//! never mutates the source environment and contains no platform-specific
//! provider logic.

pub mod apply;
pub mod backup;
pub mod capture;
pub mod capture_policy;
pub mod classify;
pub mod command;
pub mod env_schema;
pub mod env_verify;
pub mod envfile;
pub mod files;
pub mod gitmeta;
pub mod governor;
pub mod hash;
pub mod inventory;
pub mod limits;
pub mod lock;
pub mod observe;
pub mod packages;
pub mod paths;
pub mod plan;
pub mod profile;
pub mod profile_load;
pub mod profile_migrate;
pub mod redact;
pub mod rollback;
pub mod secrets;
pub mod state;
pub mod verify;

#[cfg(test)]
mod tests {
    /// Guards the crate's module wiring: every re-exported module must resolve
    /// and its core entry points must be callable.
    #[test]
    fn core_modules_are_reachable() {
        assert_eq!(crate::hash::sha256_str("configctl").len(), 64);
        assert!(crate::paths::validate_env_name("EDITOR").is_ok());
        assert!(crate::limits::Limits::default().max_depth > 0);
    }
}
