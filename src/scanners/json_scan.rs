//! Generic JSON-token file scanner: walk JSON for secret-looking string fields.

use super::util::{file_remediation, read_json, walk_json_secrets};
use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::redactor::mask_value;
use crate::scanner::{CredentialFinding, ScanResult, StorageType};
use std::path::Path;

/// Scan a JSON file, emitting a finding per secret-looking field. `cred_prefix`
/// is prepended to the dotted field path for the credential_type.
pub fn scan_json_tokens(
    path: &Path,
    tool_name: &str,
    cred_prefix: &str,
    min_len: usize,
    result: &mut ScanResult,
    show_secrets: bool,
) {
    let data = match read_json(path, result) {
        Some(d) => d,
        None => return,
    };
    let facts = FileFacts::gather(path);
    let storage = StorageType::PlaintextJson;
    let risk = assess_risk(storage, Some(&facts));
    let loc = path.display().to_string();
    let (rem, hint) = file_remediation(&facts, path);
    let staleness = facts.modified.map(describe_staleness);

    let mut hits: Vec<(String, String)> = Vec::new();
    walk_json_secrets(&data, "", min_len, &mut |field, value| {
        hits.push((field.to_string(), value.to_string()));
    });

    for (field, value) in hits {
        let mut notes = Vec::new();
        if let Some(s) = &staleness {
            notes.push(format!("File last modified: {}", s));
        }
        result.findings.push(
            CredentialFinding::new(
                tool_name,
                format!("{}{}", cred_prefix, field),
                storage,
                &loc,
                risk,
            )
            .with_preview(mask_value(&value, show_secrets))
            .with_raw(if show_secrets { Some(value) } else { None })
            .with_perms(facts.permissions.clone(), facts.owner.clone())
            .with_modified(facts.modified)
            .with_notes(notes)
            .with_remediation(rem.clone(), hint.clone()),
        );
    }
}
