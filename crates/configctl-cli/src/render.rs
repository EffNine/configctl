//! Rendering: the P0 JSON envelope and human output.

use serde::{Deserialize, Serialize};

/// The stable JSON output envelope (P0 contract).
///
/// `data` is serialized as raw JSON so the envelope stays generic over
/// per-command payloads without pulling `Deserialize` into the discovery
/// types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub schema_version: u32,
    pub command: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(default)]
    pub warnings: Vec<Warning>,
    #[serde(default)]
    pub errors: Vec<Warning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

impl Envelope {
    /// A success envelope wrapping a scan result.
    pub fn scan_ok(result: &configctl_discovery::ScanResult) -> Self {
        Self {
            schema_version: 1,
            command: "scan".into(),
            status: "ok".into(),
            data: Some(serde_json::to_value(result).unwrap_or_default()),
            warnings: result
                .warnings
                .iter()
                .map(|w| Warning {
                    code: "scan_warning".into(),
                    message: w.clone(),
                })
                .collect(),
            errors: Vec::new(),
        }
    }

    /// A success envelope wrapping a capture result.
    pub fn capture_ok(
        result: &configctl_core::capture::CaptureResult,
        written: &[String],
        out_dir: &std::path::Path,
        dry_run: bool,
    ) -> Self {
        let profile_json = serde_json::to_value(&result.profile).unwrap_or_default();
        let data = serde_json::json!({
            "profile": profile_json,
            "out_dir": out_dir.to_string_lossy(),
            "written": written,
            "dry_run": dry_run,
            "summary": serde_json::to_value(&result.summary).unwrap_or_default(),
        });
        Self {
            schema_version: 1,
            command: "capture".into(),
            status: "ok".into(),
            data: Some(data),
            warnings: result
                .summary
                .warnings
                .iter()
                .map(|w| Warning {
                    code: "capture_warning".into(),
                    message: w.clone(),
                })
                .collect(),
            errors: Vec::new(),
        }
    }

    /// An error envelope (usage/configuration errors, exit 2).
    pub fn error(command: &str, message: &str, hint: &str) -> Self {
        Self {
            schema_version: 1,
            command: command.into(),
            status: "error".into(),
            data: None,
            warnings: Vec::new(),
            errors: vec![Warning {
                code: "usage".into(),
                message: format!("{message} ({hint})"),
            }],
        }
    }

    /// Serialize to a JSON string. The redaction layer must be applied to
    /// `data` fields before this; see `ScanResult::redacted_json`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
}

/// Global CLI output flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenderConfig {
    pub json: bool,
    pub quiet: bool,
    pub verbose: bool,
}
