//! configctl-core: domain types for the read-only discovery engine.
//!
//! This crate contains the redaction subsystem, the bounded `.env` parser,
//! and the `CommandRunner` abstraction. It never performs filesystem
//! mutation and contains no platform-specific provider logic.

pub mod command;
pub mod envfile;
pub mod limits;
pub mod redact;
