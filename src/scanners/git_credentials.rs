//! Scanner for Git credential store, ~/.netrc, and gitconfig URLs.

use super::util::read_text;
use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::platform::{self, home_dir, wsl_windows_home, xdg_config_dir, Platform};
use crate::redactor::mask_value;
use crate::remediation::hint_use_credential_helper;
use crate::scanner::{CredentialFinding, ScanResult, Scanner, StorageType};
use std::path::{Path, PathBuf};

pub struct GitCredentialsScanner;

const HELPERS: &[&str] = &["osxkeychain", "manager", "libsecret"];

impl Scanner for GitCredentialsScanner {
    fn name(&self) -> &str {
        "Git Credentials"
    }
    fn slug(&self) -> &str {
        "git-credentials"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for path in credential_store_paths(plat) {
            self.scan_credentials_file(&path, &mut result, show_secrets);
        }
        for path in gitconfig_paths(plat) {
            self.scan_gitconfig(&path, &mut result, show_secrets);
        }
        result
    }
}

/// Parse `protocol://user:password@host` into (host, user, password).
fn parse_url(line: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = line.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let (authority, _) = rest.split_once('/').unwrap_or((rest, ""));
    let (userinfo, host) = authority.rsplit_once('@')?;
    let (user, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (userinfo.to_string(), String::new()),
    };
    if password.is_empty() {
        return None;
    }
    let host = host.split(':').next().unwrap_or(host).to_string();
    Some((host, user, password))
}

impl GitCredentialsScanner {
    fn scan_credentials_file(&self, path: &Path, result: &mut ScanResult, show_secrets: bool) {
        let content = match read_text(path, result) {
            Some(c) => c,
            None => return,
        };
        let facts = FileFacts::gather(path);
        let storage = StorageType::PlaintextFile;

        for (i, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((host, user, password)) = parse_url(line) {
                let mut notes = vec![
                    format!("Host: {}", host),
                    format!("Username: {}", if user.is_empty() { "(none)".into() } else { user }),
                    format!("Line: {}", i + 1),
                ];
                if let Some(m) = facts.modified {
                    notes.push(format!("File last modified: {}", describe_staleness(m)));
                }
                result.findings.push(
                    CredentialFinding::new(
                        self.name(),
                        format!("git_credential:{}", host),
                        storage,
                        path.display().to_string(),
                        assess_risk(storage, Some(&facts)),
                    )
                    .with_preview(mask_value(&password, show_secrets))
                    .with_raw(if show_secrets { Some(password) } else { None })
                    .with_perms(facts.permissions.clone(), facts.owner.clone())
                    .with_modified(facts.modified)
                    .with_notes(notes)
                    .with_remediation(
                        "Use a secure credential helper (osxkeychain, manager, libsecret) instead of plaintext store",
                        hint_use_credential_helper("git", HELPERS),
                    ),
                );
            }
        }
    }

    fn scan_gitconfig(&self, path: &Path, result: &mut ScanResult, show_secrets: bool) {
        let content = match read_text(path, result) {
            Some(c) => c,
            None => return,
        };
        let facts = FileFacts::gather(path);
        let storage = StorageType::PlaintextIni;

        // Minimal INI walk: track current section, parse `key = value`.
        let mut section = String::new();
        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_string();
                continue;
            }
            let (key, value) = match line.split_once('=') {
                Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
                None => continue,
            };
            if value.is_empty() {
                continue;
            }
            let kl = key.to_ascii_lowercase();
            let sl = section.to_ascii_lowercase();

            // 1) url = https://user:token@...
            if kl == "url" {
                if let Some((host, user, password)) = parse_url(&value) {
                    let mut notes = vec![
                        format!("Section: [{}]", section),
                        format!("Host: {}", host),
                        format!("Username: {}", if user.is_empty() { "(none)".into() } else { user }),
                    ];
                    if let Some(m) = facts.modified {
                        notes.push(format!("File last modified: {}", describe_staleness(m)));
                    }
                    result.findings.push(
                        CredentialFinding::new(
                            self.name(),
                            format!("gitconfig_url:{}", host),
                            storage,
                            path.display().to_string(),
                            assess_risk(storage, Some(&facts)),
                        )
                        .with_preview(mask_value(&password, show_secrets))
                        .with_raw(if show_secrets { Some(password) } else { None })
                        .with_perms(facts.permissions.clone(), facts.owner.clone())
                        .with_modified(facts.modified)
                        .with_notes(notes)
                        .with_remediation(
                            "Remove embedded credentials from gitconfig URL; use a credential helper instead",
                            hint_use_credential_helper("git", HELPERS),
                        ),
                    );
                }
            }

            // 2) [credential] sections: secret-looking keys
            if sl.starts_with("credential") {
                if ["helper", "username", "usehttppath"].iter().any(|t| kl.contains(t)) {
                    continue;
                }
                if ["password", "token", "secret", "key"].iter().any(|t| kl.contains(t)) {
                    let mut notes = vec![format!("Section: [{}]", section), format!("Key: {}", key)];
                    if let Some(m) = facts.modified {
                        notes.push(format!("File last modified: {}", describe_staleness(m)));
                    }
                    result.findings.push(
                        CredentialFinding::new(
                            self.name(),
                            format!("gitconfig_credential:{}", key),
                            storage,
                            path.display().to_string(),
                            assess_risk(storage, Some(&facts)),
                        )
                        .with_preview(mask_value(&value, show_secrets))
                        .with_raw(if show_secrets { Some(value.clone()) } else { None })
                        .with_perms(facts.permissions.clone(), facts.owner.clone())
                        .with_modified(facts.modified)
                        .with_notes(notes)
                        .with_remediation(
                            "Use a secure credential helper (osxkeychain, manager, libsecret) instead of plaintext store",
                            hint_use_credential_helper("git", HELPERS),
                        ),
                    );
                }
            }
        }
    }
}

fn credential_store_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![
        home.join(".git-credentials"),
        home.join(".netrc"),
        xdg_config_dir().join("git").join("credentials"),
    ];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".git-credentials"));
        }
    }
    paths
}

fn gitconfig_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![
        home.join(".gitconfig"),
        xdg_config_dir().join("git").join("config"),
    ];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".gitconfig"));
        }
    }
    paths
}
