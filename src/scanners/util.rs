//! Shared helpers for scanners.

use crate::permissions::FileFacts;
use crate::remediation::{hint_chmod, hint_manual};
use crate::scanner::ScanResult;
use serde_json::Value;
use std::path::Path;

pub const SECRET_KEYWORDS: &[&str] = &[
    "token", "key", "secret", "password", "passwd", "auth", "credential", "cred", "api_key",
    "apikey", "access_key",
];

/// Heuristic: does this key/value pair look like a secret?
pub fn looks_like_secret(key: &str, value: &str) -> bool {
    let kl = key.to_ascii_lowercase();
    if SECRET_KEYWORDS.iter().any(|kw| kl.contains(kw)) {
        return true;
    }
    if value.len() > 20 && !value.starts_with('/') && !value.starts_with("http") {
        let good = value
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_'))
            .count();
        if (good as f64) / (value.chars().count() as f64) > 0.8 {
            return true;
        }
    }
    false
}

/// Read a file to string, recording a non-fatal error on failure (but not on absence).
pub fn read_text(path: &Path, result: &mut ScanResult) -> Option<String> {
    if !path.exists() {
        return None;
    }
    match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) => {
            result
                .errors
                .push(format!("Failed to read {}: {}", path.display(), e));
            None
        }
    }
}

/// Read and parse a JSON file, recording errors as appropriate.
pub fn read_json(path: &Path, result: &mut ScanResult) -> Option<Value> {
    let content = read_text(path, result)?;
    match serde_json::from_str::<Value>(&content) {
        Ok(v) => Some(v),
        Err(e) => {
            result
                .errors
                .push(format!("Failed to parse {}: {}", path.display(), e));
            None
        }
    }
}

/// Build the standard remediation pair for a plaintext file at `path` given perms.
pub fn file_remediation(facts: &FileFacts, path: &Path) -> (String, Value) {
    if facts.permissions.as_deref() == Some("0600") {
        (
            "Credentials stored as plaintext; consider migrating to an OS credential store".to_string(),
            hint_manual("Consider migrating to an OS credential store"),
        )
    } else {
        (
            format!("Restrict file permissions: chmod 600 {}", path.display()),
            hint_chmod("600", &path.display().to_string()),
        )
    }
}

/// Recursively walk a JSON object looking for string fields whose key looks like a
/// secret, invoking `emit` for each. `prefix` builds a dotted path.
pub fn walk_json_secrets(
    value: &Value,
    prefix: &str,
    min_len: usize,
    emit: &mut dyn FnMut(&str, &str),
) {
    if let Value::Object(map) = value {
        for (k, v) in map {
            let full = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{}.{}", prefix, k)
            };
            match v {
                Value::String(s) if s.len() >= min_len => {
                    let kl = k.to_ascii_lowercase();
                    if SECRET_KEYWORDS.iter().any(|kw| kl.contains(kw))
                        || crate::redactor::identify_credential_type(s).is_some()
                    {
                        emit(&full, s);
                    }
                }
                Value::Object(_) => walk_json_secrets(v, &full, min_len, emit),
                _ => {}
            }
        }
    }
}

