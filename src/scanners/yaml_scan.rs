//! Minimal `key: value` YAML scanner for finding secret-looking keys.

use super::util::{file_remediation, looks_like_secret};
use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::redactor::mask_value;
use crate::scanner::{CredentialFinding, ScanResult, StorageType};
use std::path::Path;

/// Scan a simple YAML file for `key: value` pairs whose key looks like a secret.
pub fn scan_yaml(path: &Path, tool_name: &str, result: &mut ScanResult, show_secrets: bool) {
    if !path.exists() {
        return;
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("Failed to read {}: {}", path.display(), e));
            return;
        }
    };
    let facts = FileFacts::gather(path);

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim().trim_matches('"').trim_matches('\'')),
            None => continue,
        };
        if value.is_empty() || value == "null" || value.starts_with("${") {
            continue;
        }
        if looks_like_secret(key, value) {
            let mut notes = Vec::new();
            if let Some(m) = facts.modified {
                notes.push(format!("File last modified: {}", describe_staleness(m)));
            }
            let (rem, hint) = file_remediation(&facts, path);
            result.findings.push(
                CredentialFinding::new(
                    tool_name,
                    key.to_string(),
                    StorageType::PlaintextYaml,
                    path.display().to_string(),
                    assess_risk(StorageType::PlaintextYaml, Some(&facts)),
                )
                .with_preview(mask_value(value, show_secrets))
                .with_raw(if show_secrets { Some(value.to_string()) } else { None })
                .with_perms(facts.permissions.clone(), facts.owner.clone())
                .with_modified(facts.modified)
                .with_notes(notes)
                .with_remediation(rem, hint),
            );
        }
    }
}
