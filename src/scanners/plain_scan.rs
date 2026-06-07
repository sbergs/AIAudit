//! Helper for files whose entire contents are a single credential value.

use super::util::file_remediation;
use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::redactor::mask_value;
use crate::scanner::{CredentialFinding, ScanResult, StorageType};
use std::path::Path;

/// Treat a file's trimmed contents as one secret value.
pub fn scan_plain_token(
    path: &Path,
    tool_name: &str,
    cred_type: &str,
    result: &mut ScanResult,
    show_secrets: bool,
) {
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
    let value = content.trim();
    if value.is_empty() {
        return;
    }
    let facts = FileFacts::gather(path);
    let storage = StorageType::PlaintextFile;
    let mut notes = Vec::new();
    if let Some(m) = facts.modified {
        notes.push(format!("File last modified: {}", describe_staleness(m)));
    }
    let (rem, hint) = file_remediation(&facts, path);
    result.findings.push(
        CredentialFinding::new(
            tool_name,
            cred_type,
            storage,
            path.display().to_string(),
            assess_risk(storage, Some(&facts)),
        )
        .with_preview(mask_value(value, show_secrets))
        .with_raw(if show_secrets { Some(value.to_string()) } else { None })
        .with_perms(facts.permissions.clone(), facts.owner.clone())
        .with_modified(facts.modified)
        .with_notes(notes)
        .with_remediation(rem, hint),
    );
}
