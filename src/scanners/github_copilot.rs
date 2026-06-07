//! Scanner for GitHub Copilot / GitHub CLI credentials.

use super::util::{file_remediation, read_text};
use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::platform::{self, appdata, home_dir, wsl_windows_home, xdg_config_dir, Platform};
use crate::redactor::mask_value;
use crate::remediation::hint_use_credential_helper;
use crate::scanner::{CredentialFinding, ScanResult, Scanner, StorageType};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct GitHubCopilotScanner;

impl Scanner for GitHubCopilotScanner {
    fn name(&self) -> &str {
        "GitHub Copilot"
    }
    fn slug(&self) -> &str {
        "github-copilot"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for path in copilot_config_paths(plat) {
            self.scan_config(&path, &mut result, show_secrets);
        }
        for path in vscode_paths(plat) {
            self.scan_config(&path, &mut result, show_secrets);
        }
        result
    }
}

impl GitHubCopilotScanner {
    fn scan_config(&self, path: &Path, result: &mut ScanResult, show_secrets: bool) {
        let content = match read_text(path, result) {
            Some(c) => c,
            None => return,
        };
        let facts = FileFacts::gather(path);

        if let Ok(data) = serde_json::from_str::<Value>(&content) {
            self.extract_json(&data, path, &facts, result, show_secrets);
            return;
        }
        // YAML-ish hosts.yml: simple key: value scanning.
        for line in content.lines() {
            let stripped = line.trim();
            if let Some((key, value)) = stripped.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                if matches!(key.to_ascii_lowercase().as_str(), "oauth_token" | "token") && !value.is_empty() {
                    let storage = StorageType::PlaintextYaml;
                    let mut notes = vec!["GitHub CLI auth config".to_string()];
                    if let Some(m) = facts.modified {
                        notes.push(format!("File last modified: {}", describe_staleness(m)));
                    }
                    result.findings.push(
                        CredentialFinding::new(
                            self.name(),
                            format!("gh_cli:{}", key),
                            storage,
                            path.display().to_string(),
                            assess_risk(storage, Some(&facts)),
                        )
                        .with_preview(mask_value(value, show_secrets))
                        .with_raw(if show_secrets { Some(value.to_string()) } else { None })
                        .with_perms(facts.permissions.clone(), facts.owner.clone())
                        .with_modified(facts.modified)
                        .with_notes(notes)
                        .with_remediation(
                            "Use GitHub CLI (gh auth) for secure token storage",
                            hint_use_credential_helper("gh", &["gh auth login"]),
                        ),
                    );
                }
            }
        }
    }

    fn extract_json(
        &self,
        data: &Value,
        path: &Path,
        facts: &FileFacts,
        result: &mut ScanResult,
        show_secrets: bool,
    ) {
        let obj = match data.as_object() {
            Some(o) => o,
            None => return,
        };
        for (key, value) in obj {
            match value {
                Value::String(s) if s.len() > 10 => {
                    let kl = key.to_ascii_lowercase();
                    if ["token", "oauth", "key"].iter().any(|k| kl.contains(k)) {
                        let storage = StorageType::PlaintextJson;
                        let mut notes = Vec::new();
                        if let Some(m) = facts.modified {
                            notes.push(format!("File last modified: {}", describe_staleness(m)));
                        }
                        let (rem, hint) = file_remediation(facts, path);
                        result.findings.push(
                            CredentialFinding::new(
                                self.name(),
                                format!("copilot:{}", key),
                                storage,
                                path.display().to_string(),
                                assess_risk(storage, Some(facts)),
                            )
                            .with_preview(mask_value(s, show_secrets))
                            .with_raw(if show_secrets { Some(s.clone()) } else { None })
                            .with_perms(facts.permissions.clone(), facts.owner.clone())
                            .with_modified(facts.modified)
                            .with_notes(notes)
                            .with_remediation(rem, hint),
                        );
                    }
                }
                Value::Object(_) => self.extract_json(value, path, facts, result, show_secrets),
                _ => {}
            }
        }
    }
}

fn copilot_config_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![home.join(".copilot").join("config.json")];
    match plat {
        Platform::Linux | Platform::Wsl => {
            paths.push(xdg_config_dir().join("gh").join("hosts.yml"));
        }
        Platform::MacOs => {
            paths.push(home.join("Library").join("Application Support").join("gh").join("hosts.yml"));
        }
        Platform::Windows => {
            if let Some(ad) = appdata() {
                paths.push(ad.join("GitHub CLI").join("hosts.yml"));
            }
        }
    }
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".copilot").join("config.json"));
        }
        if let Some(ad) = appdata() {
            paths.push(ad.join("GitHub CLI").join("hosts.yml"));
        }
    }
    paths
}

fn vscode_paths(plat: Platform) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let add = |base: PathBuf, paths: &mut Vec<PathBuf>| {
        paths.push(base.join("github.copilot").join("hosts.json"));
        paths.push(base.join("github.copilot-chat").join("hosts.json"));
    };
    match plat {
        Platform::Linux | Platform::Wsl => {
            add(xdg_config_dir().join("Code").join("User").join("globalStorage"), &mut paths);
        }
        Platform::MacOs => add(
            home_dir()
                .join("Library")
                .join("Application Support")
                .join("Code")
                .join("User")
                .join("globalStorage"),
            &mut paths,
        ),
        Platform::Windows => {
            if let Some(ad) = appdata() {
                add(ad.join("Code").join("User").join("globalStorage"), &mut paths);
            }
        }
    }
    if plat == Platform::Wsl {
        if let Some(ad) = appdata() {
            add(ad.join("Code").join("User").join("globalStorage"), &mut paths);
        }
    }
    paths
}
