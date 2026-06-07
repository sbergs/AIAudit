//! Claude session/process artifact scanner.
//!
//! Surfaces presence of session state and live credentials independent of the
//! Claude Code scanner. Findings are metadata-level (no secret extraction).

use crate::permissions::{describe_staleness, FileFacts};
use crate::platform::{self, home_dir};
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult, Scanner, StorageType};

pub struct ClaudeSessionsScanner;

impl Scanner for ClaudeSessionsScanner {
    fn name(&self) -> &str {
        "Claude Sessions"
    }
    fn slug(&self) -> &str {
        "claude-sessions"
    }
    fn scan(&self, _show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        let home = home_dir();

        // Live credentials file => active session.
        let creds = home.join(".claude").join(".credentials.json");
        if creds.exists() {
            let facts = FileFacts::gather(&creds);
            let mut notes = vec!["Active Claude credentials present".to_string()];
            if let Some(m) = facts.modified {
                notes.push(format!("Last modified: {}", describe_staleness(m)));
            }
            result.findings.push(
                CredentialFinding::new(
                    self.name(),
                    "active_session",
                    StorageType::PlaintextJson,
                    creds.display().to_string(),
                    RiskLevel::Medium,
                )
                .with_perms(facts.permissions.clone(), facts.owner.clone())
                .with_modified(facts.modified)
                .with_notes(notes),
            );
        }

        // Session history directory.
        let sessions = home.join(".claude").join("sessions");
        if let Ok(entries) = std::fs::read_dir(&sessions) {
            let count = entries.flatten().count();
            if count > 0 {
                result.findings.push(
                    CredentialFinding::new(
                        self.name(),
                        "session_history",
                        StorageType::PlaintextJson,
                        sessions.display().to_string(),
                        RiskLevel::Info,
                    )
                    .with_notes(vec![format!("{} saved Claude session(s)", count)]),
                );
            }
        }

        // Project conversation history.
        let projects = home.join(".claude").join("projects");
        if projects.exists() {
            let facts = FileFacts::gather(&projects);
            result.findings.push(
                CredentialFinding::new(
                    self.name(),
                    "conversation_history",
                    StorageType::Unknown,
                    projects.display().to_string(),
                    RiskLevel::Info,
                )
                .with_modified(facts.modified)
                .with_notes(vec!["Claude project conversation transcripts present".into()]),
            );
        }

        result
    }
}
