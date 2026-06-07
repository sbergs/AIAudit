//! Scanner for Claude Code CLI credentials and MCP config secrets.

use super::util::{file_remediation, looks_like_secret, read_json};
use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::redactor::mask_value;
use crate::scanner::{CredentialFinding, ScanResult, Scanner, StorageType};
use chrono::{TimeZone, Utc};
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct ClaudeCodeScanner;

impl Scanner for ClaudeCodeScanner {
    fn name(&self) -> &str {
        "Claude Code CLI"
    }
    fn slug(&self) -> &str {
        "claude-code"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for path in credential_paths(plat) {
            self.scan_credentials_file(&path, &mut result, show_secrets);
        }

        let config_paths = config_paths(plat);
        let mut seen: HashSet<String> = HashSet::new();
        let is_backup = |p: &Path| {
            p.file_name()
                .map(|n| n.to_string_lossy().contains(".backup"))
                .unwrap_or(false)
        };
        let primary: Vec<&PathBuf> = config_paths.iter().filter(|p| !is_backup(p)).collect();
        let backups: Vec<&PathBuf> = config_paths.iter().filter(|p| is_backup(p)).collect();

        for path in &primary {
            self.scan_config_file(path, &mut result, show_secrets, &mut seen);
        }
        let backup_count = backups.iter().filter(|p| p.exists()).count();
        for path in &backups {
            self.scan_config_file(path, &mut result, show_secrets, &mut seen);
        }

        if backup_count > 0 {
            for f in &mut result.findings {
                if f.credential_type.as_str().starts_with("mcp_env:") && !f.location.contains(".backup") {
                    f.push_note(format!(
                        "Also present in {} backup file(s) under ~/.claude/backups/",
                        backup_count
                    ));
                }
            }
        }

        result
    }
}

impl ClaudeCodeScanner {
    fn scan_credentials_file(&self, path: &Path, result: &mut ScanResult, show_secrets: bool) {
        let data = match read_json(path, result) {
            Some(d) => d,
            None => return,
        };
        let facts = FileFacts::gather(path);
        match &data {
            Value::Object(_) => self.extract_auth(&data, path, &facts, result, show_secrets),
            Value::Array(entries) => {
                for e in entries {
                    if e.is_object() {
                        self.extract_auth(e, path, &facts, result, show_secrets);
                    }
                }
            }
            _ => {}
        }
    }

    fn extract_auth(
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
        let storage = StorageType::PlaintextJson;
        let risk = assess_risk(storage, Some(facts));

        let token_fields: &[(&str, &str)] = &[
            ("access", "oauth_access_token"),
            ("accessToken", "oauth_access_token"),
            ("refresh", "oauth_refresh_token"),
            ("refreshToken", "oauth_refresh_token"),
            ("apiKey", "api_key"),
            ("token", "auth_token"),
        ];

        for (field, cred_type) in token_fields {
            let value = match obj.get(*field).and_then(Value::as_str) {
                Some(v) => v,
                None => continue,
            };
            let mut notes = Vec::new();
            if let Some(t) = obj.get("type").and_then(Value::as_str) {
                notes.push(format!("Auth type: {}", t));
            }
            if let Some(m) = facts.modified {
                notes.push(format!("File last modified: {}", describe_staleness(m)));
            }

            let mut expiry = None;
            if let Some(exp) = obj.get("expires").or_else(|| obj.get("expiresAt")).and_then(Value::as_f64) {
                let secs = if exp > 1e12 { exp / 1000.0 } else { exp };
                if let Some(dt) = Utc.timestamp_opt(secs as i64, 0).single() {
                    notes.push(format!("Expires: {}", dt.format("%Y-%m-%d %H:%M UTC")));
                    expiry = Some(dt);
                }
            }

            let (rem, hint) = file_remediation(facts, path);
            result.findings.push(
                CredentialFinding::new(
                    self.name(),
                    *cred_type,
                    storage,
                    path.display().to_string(),
                    risk,
                )
                .with_preview(mask_value(value, show_secrets))
                .with_raw(if show_secrets { Some(value.to_string()) } else { None })
                .with_perms(facts.permissions.clone(), facts.owner.clone())
                .with_modified(facts.modified)
                .with_expiry(expiry)
                .with_notes(notes)
                .with_remediation(rem, hint),
            );
        }

        // Recurse into nested dicts (per-provider credentials).
        for (key, val) in obj {
            if token_fields.iter().any(|(f, _)| f == key) {
                continue;
            }
            if val.is_object() {
                self.extract_auth(val, path, facts, result, show_secrets);
            }
        }
    }

    fn scan_config_file(
        &self,
        path: &Path,
        result: &mut ScanResult,
        show_secrets: bool,
        seen: &mut HashSet<String>,
    ) {
        let data = match read_json(path, result) {
            Some(d) => d,
            None => return,
        };
        let facts = FileFacts::gather(path);
        let loc = path.display().to_string();

        let mut blocks: Vec<(&serde_json::Map<String, Value>, Option<String>)> = Vec::new();
        if let Some(top) = data.get("mcpServers").and_then(Value::as_object) {
            if !top.is_empty() {
                blocks.push((top, None));
            }
        }
        if let Some(projects) = data.get("projects").and_then(Value::as_object) {
            for (proj, cfg) in projects {
                if let Some(s) = cfg.get("mcpServers").and_then(Value::as_object) {
                    if !s.is_empty() {
                        blocks.push((s, Some(proj.clone())));
                    }
                }
            }
        }

        for (servers, project) in blocks {
            for (server_name, server_cfg) in servers {
                let env = match server_cfg.get("env").and_then(Value::as_object) {
                    Some(e) => e,
                    None => continue,
                };
                for (k, v) in env {
                    let value = match v.as_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    let dedup = format!("{}:{}:{}", server_name, k, value);
                    if !seen.insert(dedup) {
                        continue;
                    }
                    if looks_like_secret(k, value) {
                        let mut notes = vec![format!("MCP server: {}", server_name)];
                        if let Some(p) = &project {
                            notes.push(format!("Project scope: {}", p));
                        }
                        if let Some(m) = facts.modified {
                            notes.push(format!("File last modified: {}", describe_staleness(m)));
                        }
                        let (rem, hint) = file_remediation(&facts, path);
                        result.findings.push(
                            CredentialFinding::new(
                                self.name(),
                                format!("mcp_env:{}", k),
                                StorageType::PlaintextJson,
                                &loc,
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

fn credential_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![home.join(".claude").join(".credentials.json")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".claude").join(".credentials.json"));
        }
    }
    paths
}

fn config_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![
        home.join(".claude.json"),
        home.join(".claude").join("settings.json"),
    ];
    collect_backups(&home, &mut paths);
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".claude.json"));
            paths.push(win.join(".claude").join("settings.json"));
            collect_backups(&win, &mut paths);
        }
    }
    paths
}

fn collect_backups(home: &Path, paths: &mut Vec<PathBuf>) {
    let dir = home.join(".claude").join("backups");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().starts_with(".claude.json.backup") {
                paths.push(e.path());
            }
        }
    }
}
