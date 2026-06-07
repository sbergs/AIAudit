//! Scanner for Windsurf (Codeium) credentials and MCP config.

use super::util::{file_remediation, read_json};
use crate::mcp::scan_mcp_file;
use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::redactor::mask_value;
use crate::scanner::{CredentialFinding, ScanResult, Scanner, StorageType};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct WindsurfScanner;

const TOKEN_KEYS: &[&str] = &[
    "api_key", "apiKey", "token", "auth_token", "access_token", "refresh_token",
];

impl Scanner for WindsurfScanner {
    fn name(&self) -> &str {
        "Windsurf"
    }
    fn slug(&self) -> &str {
        "windsurf"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for base in config_dirs(plat) {
            self.scan_config_dir(&base, &mut result, show_secrets);
        }
        for path in mcp_paths(plat) {
            let (findings, errors) = scan_mcp_file(&path, self.name(), show_secrets);
            result.findings.extend(findings);
            result.errors.extend(errors);
        }
        result
    }
}

impl WindsurfScanner {
    fn scan_config_dir(&self, base: &Path, result: &mut ScanResult, show_secrets: bool) {
        if !base.exists() {
            return;
        }
        for fname in ["config.json", "auth.json", "credentials.json"] {
            let path = base.join(fname);
            let data = match read_json(&path, result) {
                Some(d) => d,
                None => continue,
            };
            let facts = FileFacts::gather(&path);
            if let Some(obj) = data.as_object() {
                for key in TOKEN_KEYS {
                    if let Some(value) = obj.get(*key).and_then(Value::as_str) {
                        if value.len() > 8 {
                            let mut notes = Vec::new();
                            if let Some(m) = facts.modified {
                                notes.push(format!("File last modified: {}", describe_staleness(m)));
                            }
                            let (rem, hint) = file_remediation(&facts, &path);
                            result.findings.push(
                                CredentialFinding::new(
                                    self.name(),
                                    *key,
                                    StorageType::PlaintextJson,
                                    path.display().to_string(),
                                    assess_risk(StorageType::PlaintextJson, Some(&facts)),
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
            }
        }
    }
}

fn config_dirs(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![home.join(".codeium").join("windsurf")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".codeium").join("windsurf"));
        }
    }
    paths
}

fn mcp_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![home.join(".codeium").join("windsurf").join("mcp_config.json")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".codeium").join("windsurf").join("mcp_config.json"));
        }
    }
    paths
}
