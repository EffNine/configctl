//! Deterministic multi-signal secret detector.
//!
//! Classification is one of: `secret`, `likely_secret`, `config`, `unknown`.
//!
//! Signals (see P1 spec §4):
//! - A: variable-name lexicon (extensible registry, not provider-hardcoded)
//! - B: known token patterns (PEM, JWT, high-entropy prefixes)
//! - C: entropy (supporting evidence only; never the sole signal)
//! - D: context (file name layer)
//!
//! The detector operates on `ParsedVariable` and never returns the value.
//! `classify_value` is a private helper that takes `&str` and returns only
//! classification + signals. The public API accepts `&ParsedVariable`.

use configctl_core::envfile::ParsedVariable;

/// Variable classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Secret,
    LikelySecret,
    Config,
    Unknown,
}

impl Classification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Classification::Secret => "secret",
            Classification::LikelySecret => "likely_secret",
            Classification::Config => "config",
            Classification::Unknown => "unknown",
        }
    }
}

/// A classification result with the contributing signals.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClassificationResult {
    pub classification: Classification,
    pub signals: Vec<String>,
}

impl ClassificationResult {
    pub fn is_secret_like(&self) -> bool {
        matches!(
            self.classification,
            Classification::Secret | Classification::LikelySecret
        )
    }
}

/// A name-lexicon entry.
pub struct NamePattern {
    /// Substring matched in the (uppercased) variable name.
    pub needle: &'static str,
    /// Classification when only the name signal fires.
    pub weight: &'static str,
}

/// Built-in name lexicon. Grows by appending; the architecture never
/// hard-codes a provider into the detection flow.
pub const NAME_LEXICON: &[NamePattern] = &[
    NamePattern {
        needle: "API_KEY",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "APIKEY",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "ACCESS_TOKEN",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "AUTH_TOKEN",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "AUTHORISATION",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "AUTHORIZATION",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "PRIVATE_KEY",
        weight: "secret",
    },
    NamePattern {
        needle: "SECRET_KEY",
        weight: "secret",
    },
    NamePattern {
        needle: "CLIENT_SECRET",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "PASSPHRASE",
        weight: "secret",
    },
    NamePattern {
        needle: "PASSWORD",
        weight: "secret",
    },
    NamePattern {
        needle: "PASSWD",
        weight: "secret",
    },
    NamePattern {
        needle: "SECRET",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "TOKEN",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "DATABASE_URL",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "DB_PASSWORD",
        weight: "secret",
    },
    NamePattern {
        needle: "DB_PASS",
        weight: "secret",
    },
    NamePattern {
        needle: "DB_PASSWD",
        weight: "secret",
    },
    NamePattern {
        needle: "DB_USER",
        weight: "config",
    },
    NamePattern {
        needle: "AWS_ACCESS_KEY_ID",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "AWS_SECRET_ACCESS_KEY",
        weight: "secret",
    },
    NamePattern {
        needle: "GITHUB_TOKEN",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "GITHUB_PAT",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "OPENAI_API_KEY",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "ANTHROPIC_API_KEY",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "HUGGINGFACE_TOKEN",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "HF_TOKEN",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "SLACK_TOKEN",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "STRIPE_SECRET_KEY",
        weight: "secret",
    },
    NamePattern {
        needle: "STRIPE_KEY",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "GOOGLE_API_KEY",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "CREDENTIAL",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "CREDENTIALS",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "KEY",
        weight: "likely_secret",
    },
    NamePattern {
        needle: "CERT",
        weight: "config",
    },
];

/// Classify a parsed variable using all four signals.
pub fn classify_variable(
    var: &ParsedVariable,
    file_stem: &str,
    scorer: &EntropyScorer,
) -> ClassificationResult {
    let mut signals: Vec<String> = Vec::new();
    let mut best: Classification = Classification::Unknown;

    // Signal A: variable name
    let name = var.name.to_uppercase();
    let mut best_needle_len = 0usize;
    let mut name_hit: Option<&'static str> = None;
    for e in NAME_LEXICON {
        if name.contains(e.needle) && e.needle.len() > best_needle_len {
            best_needle_len = e.needle.len();
            name_hit = Some(e.weight);
        }
    }

    // Signal B: known token patterns
    let pattern_hit = var.with_value(token_pattern_hit);

    // Signal C: entropy (supporting only)
    let entropy_signal: bool;
    let entropy_value: f64;
    {
        let e = scorer;
        (entropy_signal, entropy_value) = var.with_value(|v| e.score(v));
    }

    // Signal D: context (file stem)
    let ctx_hit = file_stem.contains("env");

    if let Some(w) = name_hit {
        signals.push(format!("variable_name: {}", var.name));
        best = bump(best, weight_class(w));
    }
    if let Some(p) = &pattern_hit {
        signals.push(format!("token_pattern: {p}"));
        best = bump(best, Classification::Secret);
    }
    if entropy_signal {
        signals.push(format!("high_entropy({entropy_value:.1})",));
        // Entropy alone is supporting evidence: at most likely_secret.
        if !best_is_secret(best) {
            best = Classification::LikelySecret;
        }
    }
    if ctx_hit {
        signals.push("context:env_file".into());
    }

    // Empty values are config (not secret).
    if var.value_is_empty() {
        return ClassificationResult {
            classification: Classification::Config,
            signals: vec!["empty_value".to_string()],
        };
    }

    // No signals fired at all.
    if signals.is_empty() {
        best = Classification::Config;
        signals.push("no_secret_signals".into());
    }

    ClassificationResult {
        classification: best,
        signals,
    }
}

fn weight_class(w: &'static str) -> Classification {
    match w {
        "secret" => Classification::Secret,
        "likely_secret" => Classification::LikelySecret,
        _ => Classification::Config,
    }
}

fn best_is_secret(c: Classification) -> bool {
    matches!(c, Classification::Secret)
}

fn bump(cur: Classification, new: Classification) -> Classification {
    if rank(new) > rank(cur) {
        new
    } else {
        cur
    }
}

fn rank(c: Classification) -> u8 {
    match c {
        Classification::Unknown => 0,
        Classification::Config => 1,
        Classification::LikelySecret => 2,
        Classification::Secret => 3,
    }
}

/// Detect obvious token shapes without the value in the signal name.
fn token_pattern_hit(value: &str) -> Option<&'static str> {
    let v = value.trim();
    // PEM private key block
    if v.contains("BEGIN PRIVATE KEY")
        || v.contains("BEGIN RSA PRIVATE KEY")
        || v.contains("BEGIN OPENSSH PRIVATE KEY")
    {
        return Some("pem_private_key");
    }
    // JWT: three non-empty base64url segments (never an email address).
    if v.len() > 20
        && !v.contains(' ')
        && !v.contains('@')
        && v.chars().filter(|&c| c == '.').count() == 2
    {
        let segs: Vec<&str> = v.split('.').collect();
        if segs.len() == 3
            && segs.iter().all(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
            })
        {
            return Some("jwt_like");
        }
    }
    // AWS access key: AKIA / ASIA + 16 alphanumerics
    if (v.starts_with("AKIA") || v.starts_with("ASIA"))
        && v.len() == 20
        && v.chars().skip(4).all(|c| c.is_ascii_alphanumeric())
    {
        return Some("aws_access_key");
    }
    // High-confidence prefixes (kept short to avoid value echo)
    if v.starts_with("sk-") || v.starts_with("pk-") {
        return Some("openai_style_key");
    }
    if v.starts_with("ghp_") || v.starts_with("gho_") || v.starts_with("github_pat_") {
        return Some("github_token");
    }
    if v.starts_with("xoxb-") || v.starts_with("xoxp-") {
        return Some("slack_token");
    }
    if v.starts_with("sk_live_") || v.starts_with("sk_test_") {
        return Some("stripe_key");
    }
    None
}

/// Entropy scorer (Shannon, bits/char). High entropy is supporting evidence
/// only, never a sole secret signal.
pub struct EntropyScorer {
    /// Minimum bits/char to count as "high entropy".
    pub threshold: f64,
    /// Minimum value length to even consider entropy.
    pub min_len: usize,
}

impl Default for EntropyScorer {
    fn default() -> Self {
        Self {
            threshold: 4.2,
            min_len: 12,
        }
    }
}

impl EntropyScorer {
    pub fn new(threshold: f64, min_len: usize) -> Self {
        Self { threshold, min_len }
    }

    /// `(is_high, value)`. Entropy is computed over the raw value; the value
    /// is returned as a number only, never the content.
    pub fn score(&self, value: &str) -> (bool, f64) {
        if value.len() < self.min_len {
            return (false, 0.0);
        }
        let bytes = value.as_bytes();
        let len = bytes.len() as f64;
        let mut freq: std::collections::HashMap<u8, f64> = std::collections::HashMap::new();
        for &b in bytes {
            *freq.entry(b).or_insert(0.0) += 1.0;
        }
        let mut entropy = 0.0;
        for &f in freq.values() {
            let p = f / len;
            if p > 0.0 {
                entropy += -p * p.log2();
            }
        }
        (entropy >= self.threshold, entropy)
    }
}
