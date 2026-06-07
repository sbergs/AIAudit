//! Scanner for Docker credentials in ~/.docker/config.json.

use super::util::read_json;
use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::redactor::mask_value;
use crate::remediation::hint_use_credential_helper;
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult, Scanner, StorageType};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct DockerScanner;

const HELPERS: &[&str] = &["osxkeychain", "pass", "secretservice"];
const REM: &str = "Use docker credential helpers (credsStore) instead of storing tokens in config.json. See: docker login --help";

impl Scanner for DockerScanner {
    fn name(&self) -> &str {
        "Docker"
    }
    fn slug(&self) -> &str {
        "docker"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for path in config_paths(plat) {
            self.scan_config(&path, &mut result, show_secrets);
        }
        result
    }
}

impl DockerScanner {
    #[allow(clippy::too_many_arguments)]
    fn finding(
        &self,
        cred_type: String,
        storage: StorageType,
        path: &Path,
        facts: &FileFacts,
        risk: RiskLevel,
        value: &str,
        masked: String,
        show_secrets: bool,
        notes: Vec<String>,
    ) -> CredentialFinding {
        CredentialFinding::new(self.name(), cred_type, storage, path.display().to_string(), risk)
            .with_preview(masked)
            .with_raw(if show_secrets { Some(value.to_string()) } else { None })
            .with_perms(facts.permissions.clone(), facts.owner.clone())
            .with_modified(facts.modified)
            .with_notes(notes)
            .with_remediation(REM, hint_use_credential_helper("docker", HELPERS))
    }

    fn scan_config(&self, path: &Path, result: &mut ScanResult, show_secrets: bool) {
        let data = match read_json(path, result) {
            Some(d) => d,
            None => return,
        };
        let obj = match data.as_object() {
            Some(o) => o,
            None => return,
        };
        let facts = FileFacts::gather(path);
        let storage = StorageType::PlaintextJson;
        let staleness = facts.modified.map(|m| format!("File last modified: {}", describe_staleness(m)));

        // 1) auths
        if let Some(auths) = obj.get("auths").and_then(Value::as_object) {
            for (registry, entry) in auths {
                let entry = match entry.as_object() {
                    Some(e) => e,
                    None => continue,
                };
                if let Some(auth) = entry.get("auth").and_then(Value::as_str) {
                    if !auth.is_empty() {
                        let mut notes = vec![
                            format!("Registry: {}", registry),
                            "Base64(user:password) stored in plaintext".into(),
                        ];
                        if let Some(s) = &staleness {
                            notes.push(s.clone());
                        }
                        result.findings.push(self.finding(
                            format!("registry_auth:{}", registry),
                            storage,
                            path,
                            &facts,
                            assess_risk(storage, Some(&facts)),
                            auth,
                            mask_value(auth, show_secrets),
                            show_secrets,
                            notes,
                        ));
                    }
                }
                if let Some(tok) = entry.get("identitytoken").and_then(Value::as_str) {
                    if !tok.is_empty() {
                        let mut notes = vec![
                            format!("Registry: {}", registry),
                            "Docker identity token (OAuth refresh-like)".into(),
                        ];
                        if let Some(s) = &staleness {
                            notes.push(s.clone());
                        }
                        result.findings.push(self.finding(
                            format!("registry_identitytoken:{}", registry),
                            storage,
                            path,
                            &facts,
                            assess_risk(storage, Some(&facts)),
                            tok,
                            mask_value(tok, show_secrets),
                            show_secrets,
                            notes,
                        ));
                    }
                }
                for (sk, sv) in entry {
                    if matches!(sk.as_str(), "auth" | "identitytoken" | "email" | "username") {
                        continue;
                    }
                    if let Some(s) = sv.as_str() {
                        let lk = sk.to_ascii_lowercase();
                        if s.len() > 20 && ["token", "secret", "key", "password"].iter().any(|k| lk.contains(k)) {
                            let mut notes = vec![format!("Registry: {}", registry), format!("Field: {}", sk)];
                            if let Some(st) = &staleness {
                                notes.push(st.clone());
                            }
                            result.findings.push(self.finding(
                                format!("registry_{}:{}", sk, registry),
                                storage,
                                path,
                                &facts,
                                assess_risk(storage, Some(&facts)),
                                s,
                                mask_value(s, show_secrets),
                                show_secrets,
                                notes,
                            ));
                        }
                    }
                }
            }
        }

        // 2) credsStore
        if let Some(cs) = obj.get("credsStore").and_then(Value::as_str) {
            if !cs.is_empty() {
                let mut notes = vec![
                    format!("Using credential helper: docker-credential-{}", cs),
                    "Credentials stored outside config.json (likely in OS keystore)".into(),
                ];
                if let Some(s) = &staleness {
                    notes.push(s.clone());
                }
                result.findings.push(
                    CredentialFinding::new(self.name(), "credsStore", StorageType::Unknown, path.display().to_string(), RiskLevel::Info)
                        .with_preview(cs)
                        .with_perms(facts.permissions.clone(), facts.owner.clone())
                        .with_modified(facts.modified)
                        .with_notes(notes)
                        .with_remediation(REM, hint_use_credential_helper("docker", HELPERS)),
                );
            }
        }

        // 3) credHelpers
        if let Some(helpers) = obj.get("credHelpers").and_then(Value::as_object) {
            for (registry, helper) in helpers {
                if let Some(h) = helper.as_str() {
                    let mut notes = vec![
                        format!("Registry: {}", registry),
                        format!("Using credential helper: docker-credential-{}", h),
                        "Credentials stored outside config.json (likely in OS keystore)".into(),
                    ];
                    if let Some(s) = &staleness {
                        notes.push(s.clone());
                    }
                    result.findings.push(
                        CredentialFinding::new(self.name(), format!("credHelper:{}", registry), StorageType::Unknown, path.display().to_string(), RiskLevel::Info)
                            .with_preview(h)
                            .with_perms(facts.permissions.clone(), facts.owner.clone())
                            .with_modified(facts.modified)
                            .with_notes(notes)
                            .with_remediation(REM, hint_use_credential_helper("docker", HELPERS)),
                    );
                }
            }
        }

        // 4) top-level + nested secret-looking keys
        for (key, val) in obj {
            if matches!(key.as_str(), "auths" | "credsStore" | "credHelpers") {
                continue;
            }
            match val {
                Value::String(s) if s.len() > 20 => {
                    let lk = key.to_ascii_lowercase();
                    if ["token", "secret", "key", "password", "auth"].iter().any(|k| lk.contains(k)) {
                        let mut notes = vec![format!("Top-level field: {}", key)];
                        if let Some(st) = &staleness {
                            notes.push(st.clone());
                        }
                        result.findings.push(self.finding(
                            format!("config:{}", key),
                            storage,
                            path,
                            &facts,
                            assess_risk(storage, Some(&facts)),
                            s,
                            mask_value(s, show_secrets),
                            show_secrets,
                            notes,
                        ));
                    }
                }
                Value::Object(_) => {
                    self.recurse(val, path, &facts, result, show_secrets, key, &staleness, 0);
                }
                _ => {}
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recurse(
        &self,
        data: &Value,
        path: &Path,
        facts: &FileFacts,
        result: &mut ScanResult,
        show_secrets: bool,
        prefix: &str,
        staleness: &Option<String>,
        depth: usize,
    ) {
        if depth > 4 {
            return;
        }
        let obj = match data.as_object() {
            Some(o) => o,
            None => return,
        };
        for (key, val) in obj {
            let full = format!("{}.{}", prefix, key);
            match val {
                Value::Object(_) => self.recurse(val, path, facts, result, show_secrets, &full, staleness, depth + 1),
                Value::String(s) if s.len() > 20 => {
                    let lk = key.to_ascii_lowercase();
                    if ["token", "secret", "key", "password", "auth"].iter().any(|k| lk.contains(k)) {
                        let mut notes = vec![format!("Nested field: {}", full)];
                        if let Some(st) = staleness {
                            notes.push(st.clone());
                        }
                        result.findings.push(self.finding(
                            format!("config:{}", full),
                            StorageType::PlaintextJson,
                            path,
                            facts,
                            assess_risk(StorageType::PlaintextJson, Some(facts)),
                            s,
                            mask_value(s, show_secrets),
                            show_secrets,
                            notes,
                        ));
                    }
                }
                _ => {}
            }
        }
    }
}

fn config_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![home.join(".docker").join("config.json")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".docker").join("config.json"));
        }
    }
    paths
}
