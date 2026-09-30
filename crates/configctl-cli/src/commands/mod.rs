//! CLI command handlers.

pub mod apply;
pub mod audit;
pub mod capture;
pub mod common;
pub mod doctor;
pub mod env;
pub mod init;
pub mod onboard;
pub mod plan;
pub mod profile;
pub mod rollback;
pub mod scan;
pub mod secrets;
pub mod status;
pub mod verify;
pub mod why;

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the handler-module surface: every module re-declared here must
    /// remain publicly reachable (a removal is a compile error in the CLI).
    #[test]
    fn command_modules_are_public() {
        let _ = std::any::type_name::<status::StatusOutput>();
        let _ = std::any::type_name::<verify::VerifyOutput>();
    }
}
