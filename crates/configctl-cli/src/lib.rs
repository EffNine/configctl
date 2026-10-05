//! configctl-cli: argument parsing, command handlers, rendering, exit codes.

pub mod commands;
pub mod guidance;
pub mod render;
pub mod tui;
pub use render::Envelope;

#[cfg(test)]
mod tests {
    use super::*;

    /// The library surface used by `main.rs` must stay reachable, and the JSON
    /// envelope constructors must produce a stable shape.
    #[test]
    fn cli_library_surface_is_reachable() {
        let ok = Envelope::ok("status", serde_json::json!({"exit": 0}));
        assert_eq!(ok.command, "status");
        assert_eq!(ok.status, "ok");
        let _ = crate::guidance::Topic::ALL.len();
        let _ = std::any::type_name::<crate::commands::status::StatusOutput>();
    }
}
