//! Explicit one-way profile migration (v1 → v2).
//!
//! Old profiles are never silently reinterpreted: loading a v1 bundle works
//! through the compatibility layer, and `configctl profile migrate --to 2`
//! performs the only supported transition — stamping the schema version and
//! recording provenance. Content semantics are unchanged (all v2 additions
//! are defaulted sections).

use crate::profile::{ProvenanceSection, Profile, SCHEMA_VERSION, SCHEMA_VERSION_V1};

/// Migrate an in-memory profile to schema v2.
///
/// Returns `Ok(true)` when a migration was applied, `Ok(false)` when the
/// profile is already at v2, and `Err` for anything else (never migrates
/// forward from unknown versions or backward).
pub fn migrate_to_v2(profile: &mut Profile) -> Result<bool, String> {
    if profile.schema_version == SCHEMA_VERSION {
        return Ok(false);
    }
    if profile.schema_version != SCHEMA_VERSION_V1 {
        return Err(format!(
            "cannot migrate schema_version {} (only v1 → v2 is supported)",
            profile.schema_version
        ));
    }
    profile.schema_version = SCHEMA_VERSION;
    profile.provenance = Some(ProvenanceSection {
        source: profile
            .provenance
            .as_ref()
            .map(|p| p.source.clone())
            .unwrap_or_else(|| "migrate".to_string()),
        migrated_from: Some(SCHEMA_VERSION_V1),
    });
    Ok(true)
}

/// Validate that a TOML bundle declares a supported schema version without
/// fully parsing it (cheap pre-check for tooling).
pub fn declared_schema_version(text: &str) -> Result<u32, String> {
    let value: toml::Value = toml::from_str(text).map_err(|e| format!("profile parse: {e}"))?;
    value
        .get("schema_version")
        .and_then(|v| v.as_integer())
        .map(|v| v as u32)
        .ok_or_else(|| "profile has no integer schema_version".to_string())
}
