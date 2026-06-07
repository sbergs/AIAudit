//! Shared MCP (Model Context Protocol) config parser.
//!
//! Used by Cursor, Cline, Windsurf, Claude Desktop, etc. Extracts inline
//! secrets from `mcpServers[*].env`, `.headers`, and `.args`.

use crate::permissions::{assess_risk, describe_staleness, FileFacts};
use crate::redactor::mask_value;
use crate::remediation::{hint_manual, hint_migrate_to_env};
use crate::scanner::{CredentialFinding, RiskLevel, StorageType};
use serde_json::Value;
use std::path::Path;

const SECRET_KEY_PATTERNS: &[&str] = &[
    "token", "key", "secret", "password", "passwd", "auth", "credential", "cred", "api_key",
    "apikey", "access_key", "bearer", "jwt",
];

/// Env var names that are never secrets — runtime/path/locale plumbing.
const KNOWN_NON_SECRET_KEYS: &[&str] = &[
    "PATH", "PYTHONPATH", "NODE_PATH", "CLASSPATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
    "GOPATH", "GOROOT", "GOBIN", "CARGO_HOME", "RUSTUP_HOME", "HOME", "USER", "USERNAME",
    "LOGNAME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE",
    "LC_MESSAGES", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY", "TZ", "TMP", "TMPDIR",
    "TEMP", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "SHELL",
    "TERM", "TERM_PROGRAM", "PWD", "OLDPWD", "DISPLAY", "WAYLAND_DISPLAY", "COLORTERM", "DEBUG",
    "VERBOSE", "LOG_LEVEL", "LOGLEVEL", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "NODE_ENV",
    "RUST_LOG", "RUST_BACKTRACE", "NODE_OPTIONS", "NPM_CONFIG_PREFIX", "CI", "GITHUB_ACTIONS",
    "RUNNER_OS", "OS", "OSTYPE", "MACHTYPE", "PROCESSOR_ARCHITECTURE", "SYSTEMROOT", "WINDIR",
    "COMSPEC",
];

fn is_env_var_reference(value: &str) -> bool {
    value.contains("${")
}

pub fn looks_like_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEY_PATTERNS.iter().any(|p| lower.contains(p))
}

pub fn looks_like_secret_value(value: &str) -> bool {
    if value.len() < 20 {
        return false;
    }
    if value.starts_with('/') || value.starts_with("http") {
        return false;
    }
    if value.starts_with('@') && value.contains('/') {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        return false;
    }
    let good = value
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .count();
    (good as f64) / (value.chars().count() as f64) > 0.8
}

/// Parse a single MCP config file. Returns (findings, errors).
pub fn scan_mcp_file(
    path: &Path,
    tool_name: &str,
    show_secrets: bool,
) -> (Vec<CredentialFinding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    if !path.exists() {
        return (findings, errors);
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            errors.push(format!("Failed to read MCP config {}: {}", path.display(), e));
            return (findings, errors);
        }
    };
    let data: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("Failed to parse MCP config {}: {}", path.display(), e));
            return (findings, errors);
        }
    };

    if let Value::Object(_) = data {
        let facts = FileFacts::gather(path);
        parse_mcp_config(&data, path, tool_name, show_secrets, &facts, &mut findings);
    }

    (findings, errors)
}

fn collect_mcp_blocks(data: &Value) -> Vec<(&serde_json::Map<String, Value>, String)> {
    let mut blocks = Vec::new();
    if let Some(top) = data.get("mcpServers").and_then(Value::as_object) {
        if !top.is_empty() {
            blocks.push((top, String::new()));
        }
    }
    if let Some(projects) = data.get("projects").and_then(Value::as_object) {
        for (proj_path, cfg) in projects {
            if let Some(servers) = cfg.get("mcpServers").and_then(Value::as_object) {
                if !servers.is_empty() {
                    blocks.push((servers, proj_path.clone()));
                }
            }
        }
    }
    blocks
}

fn parse_mcp_config(
    data: &Value,
    path: &Path,
    tool_name: &str,
    show_secrets: bool,
    facts: &FileFacts,
    findings: &mut Vec<CredentialFinding>,
) {
    let loc = path.display().to_string();
    let staleness = facts.modified.map(describe_staleness);

    for (servers, project_path) in collect_mcp_blocks(data) {
        for (server_name, server_cfg) in servers {
            let server_cfg = match server_cfg.as_object() {
                Some(o) => o,
                None => continue,
            };

            let build_notes = |extra: &str| -> Vec<String> {
                let mut notes = vec![format!("MCP server: {}", server_name)];
                if !project_path.is_empty() {
                    notes.push(format!("Project scope: {}", project_path));
                }
                notes.push(extra.to_string());
                if let Some(s) = &staleness {
                    notes.push(format!("Config last modified {}", s));
                }
                notes
            };

            // env block
            if let Some(env) = server_cfg.get("env").and_then(Value::as_object) {
                for (key, value) in env {
                    let value = match value.as_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    if KNOWN_NON_SECRET_KEYS.contains(&key.to_ascii_uppercase().as_str()) {
                        continue;
                    }
                    if is_env_var_reference(value) {
                        let f = CredentialFinding::new(
                            tool_name,
                            format!("mcp_env_ref:{}", key),
                            StorageType::PlaintextJson,
                            &loc,
                            RiskLevel::Info,
                        )
                        .with_preview(value)
                        .with_modified(facts.modified)
                        .with_notes(build_notes("References environment variable (not inline secret)"))
                        .with_remediation(
                            "Verify env var is set in a secure environment, not committed to source",
                            hint_manual("Verify env var is set in a secure environment, not committed to source"),
                        );
                        findings.push(f);
                    } else if looks_like_secret_key(key) || looks_like_secret_value(value) {
                        let f = CredentialFinding::new(
                            tool_name,
                            format!("mcp_env:{}", key),
                            StorageType::PlaintextJson,
                            &loc,
                            assess_risk(StorageType::PlaintextJson, Some(facts)),
                        )
                        .with_preview(mask_value(value, show_secrets))
                        .with_raw(if show_secrets { Some(value.to_string()) } else { None })
                        .with_perms(facts.permissions.clone(), facts.owner.clone())
                        .with_modified(facts.modified)
                        .with_notes(build_notes("Inline secret in config"))
                        .with_remediation(
                            "Move secret to environment variable or secret manager",
                            hint_migrate_to_env(vec![], &loc),
                        );
                        findings.push(f);
                    }
                }
            }

            // headers block
            if let Some(headers) = server_cfg.get("headers").and_then(Value::as_object) {
                for (key, value) in headers {
                    let value = match value.as_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    let kl = key.to_ascii_lowercase();
                    if !matches!(kl.as_str(), "authorization" | "x-api-key" | "api-key") {
                        continue;
                    }
                    if is_env_var_reference(value) {
                        findings.push(
                            CredentialFinding::new(
                                tool_name,
                                format!("mcp_header:{}", key),
                                StorageType::PlaintextJson,
                                &loc,
                                RiskLevel::Info,
                            )
                            .with_preview(value)
                            .with_modified(facts.modified)
                            .with_notes(build_notes("References environment variable"))
                            .with_remediation(
                                "Verify env var is set in a secure environment, not committed to source",
                                hint_manual("Verify env var is set in a secure environment, not committed to source"),
                            ),
                        );
                    } else {
                        findings.push(
                            CredentialFinding::new(
                                tool_name,
                                format!("mcp_header:{}", key),
                                StorageType::PlaintextJson,
                                &loc,
                                assess_risk(StorageType::PlaintextJson, Some(facts)),
                            )
                            .with_preview(mask_value(value, show_secrets))
                            .with_raw(if show_secrets { Some(value.to_string()) } else { None })
                            .with_perms(facts.permissions.clone(), facts.owner.clone())
                            .with_modified(facts.modified)
                            .with_notes(build_notes("Inline auth header"))
                            .with_remediation(
                                "Move secret to environment variable or secret manager",
                                hint_migrate_to_env(vec![], &loc),
                            ),
                        );
                    }
                }
            }

            // args
            if let Some(args) = server_cfg.get("args").and_then(Value::as_array) {
                for (i, arg) in args.iter().enumerate() {
                    let arg = match arg.as_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    if looks_like_secret_value(arg) && !arg.starts_with('-') {
                        findings.push(
                            CredentialFinding::new(
                                tool_name,
                                format!("mcp_arg[{}]", i),
                                StorageType::PlaintextJson,
                                &loc,
                                assess_risk(StorageType::PlaintextJson, Some(facts)),
                            )
                            .with_preview(mask_value(arg, show_secrets))
                            .with_raw(if show_secrets { Some(arg.to_string()) } else { None })
                            .with_perms(facts.permissions.clone(), facts.owner.clone())
                            .with_modified(facts.modified)
                            .with_notes(build_notes(&format!("Token in CLI arg position {}", i))),
                        );
                    }
                }
            }
        }
    }
}
