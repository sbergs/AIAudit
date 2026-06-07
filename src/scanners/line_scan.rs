//! Shared logic for scanners that read files line by line looking for secrets.

use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::redactor::{identify_credential_type, line_matches_assignment, redact_line};
use crate::remediation::hint_manual;
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult, StorageType};
use std::path::Path;

/// Does this line look like it contains a secret? Returns whether the value
/// matched a known credential prefix (for risk escalation).
pub fn line_secret_match(line: &str) -> Option<bool> {
    // Known-prefix tokens are the strongest signal.
    let has_known_prefix = crate::redactor::KNOWN_PREFIXES.iter().any(|(p, _)| {
        line.contains(p)
            && line
                .split(|c: char| !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '+' | '=')))
                .any(|tok| tok.starts_with(p) && tok.len() >= p.len() + 12)
    });
    if has_known_prefix {
        return Some(true);
    }
    if line_matches_assignment(line) {
        return Some(false);
    }
    None
}

/// Scan one file's lines and append findings. `storage` and `base_risk`
/// configure the finding shape. `tool_name` is the owning scanner's name.
pub fn scan_lines(
    path: &Path,
    tool_name: &str,
    storage: StorageType,
    result: &mut ScanResult,
    _show_secrets: bool,
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
    let facts = FileFacts::gather(path);

    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let known_prefix = match line_secret_match(line) {
            Some(kp) => kp,
            None => continue,
        };

        let mut risk = assess_risk(storage, Some(&facts));
        if known_prefix && risk > RiskLevel::High {
            risk = RiskLevel::High;
        }

        // The preview is always the redacted line; raw values are never emitted
        // from history/log files even with --show-secrets, since the surrounding
        // command text could leak other data.
        let preview = redact_line(line);
        let cred_kind = identify_credential_type(line).unwrap_or("secret in line");

        let mut notes = vec![format!("Line: {}", i + 1)];
        if known_prefix {
            notes.push("Matched a known credential prefix".to_string());
        }
        if let Some(m) = facts.modified {
            notes.push(format!("File last modified: {}", describe_staleness(m)));
        }

        result.findings.push(
            CredentialFinding::new(
                tool_name,
                cred_kind,
                storage,
                path.display().to_string(),
                risk,
            )
            .with_preview(preview)
            .with_perms(facts.permissions.clone(), facts.owner.clone())
            .with_modified(facts.modified)
            .with_notes(notes)
            .with_remediation(
                "Remove the secret from this file and rotate the credential; use a secret manager instead",
                hint_manual("Remove secret from file and rotate credential"),
            ),
        );
    }
}
