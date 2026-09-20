//! configctl-core: domain types for discovery + declarative capture.
//!
//! This crate contains the redaction subsystem, the bounded `.env` parser,
//! the `CommandRunner` abstraction, and the P2 profile/capture model. It
//! never mutates the source environment and contains no platform-specific
//! provider logic.

pub mod capture;
pub mod command;
pub mod env_schema;
pub mod envfile;
pub mod files;
pub mod gitmeta;
pub mod limits;
pub mod packages;
pub mod paths;
pub mod profile;
pub mod redact;
