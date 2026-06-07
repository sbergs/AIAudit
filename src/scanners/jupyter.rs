//! Jupyter scanner: server config tokens/passwords and kernel.json secrets.

use super::json_scan::scan_json_tokens;
use crate::permissions::{assess_risk, FileFacts};
use crate::platform::{self, appdata, home_dir, wsl_windows_home, Platform};
use crate::redactor::mask_value;
use crate::remediation::hint_manual;
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult, Scanner, StorageType};
use std::path::PathBuf;

pub struct JupyterScanner;

impl Scanner for JupyterScanner {
    fn name(&self) -> &str {
        "Jupyter"
    }
    fn slug(&self) -> &str {
        "jupyter"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for path in config_paths(plat) {
            self.scan_config(&path, &mut result, show_secrets);
        }
        for dir in kernel_dirs(plat) {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    let kj = e.path().join("kernel.json");
                    scan_json_tokens(&kj, self.name(), "kernel:", 8, &mut result, show_secrets);
                }
            }
        }
        result
    }
}

impl JupyterScanner {
    fn scan_config(&self, path: &std::path::Path, result: &mut ScanResult, show_secrets: bool) {
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

        // Jupyter config is a Python file with lines like:
        //   c.ServerApp.token = '...'  /  c.ServerApp.password = '...'
        for raw in content.lines() {
            let line = raw.trim();
            let lower = line.to_ascii_lowercase();
            let kind = if lower.contains(".token") && line.contains('=') {
                Some("token")
            } else if lower.contains(".password") && line.contains('=') {
                Some("password")
            } else {
                None
            };
            if let Some(kind) = kind {
                if let Some((_, rhs)) = line.split_once('=') {
                    let value = rhs.trim().trim_matches(|c| c == '\'' || c == '"');
                    if value.is_empty() {
                        continue;
                    }
                    let storage = StorageType::PlaintextFile;
                    // Empty token => open server (handled above by skip). Non-empty
                    // token here means a credential is present.
                    let risk = if value.len() < 8 {
                        RiskLevel::High
                    } else {
                        assess_risk(storage, Some(&facts))
                    };
                    result.findings.push(
                        CredentialFinding::new(
                            self.name(),
                            format!("server_{}", kind),
                            storage,
                            path.display().to_string(),
                            risk,
                        )
                        .with_preview(mask_value(value, show_secrets))
                        .with_raw(if show_secrets { Some(value.to_string()) } else { None })
                        .with_perms(facts.permissions.clone(), facts.owner.clone())
                        .with_modified(facts.modified)
                        .with_notes(vec!["Jupyter server credential in config".into()])
                        .with_remediation(
                            "Use a strong token and restrict network binding",
                            hint_manual("Use a strong Jupyter token and bind to localhost"),
                        ),
                    );
                }
            }
        }
    }
}

fn config_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let names = [
        "jupyter_server_config.py",
        "jupyter_notebook_config.py",
        "jupyter_server_config.json",
        "jupyter_notebook_config.json",
    ];
    let mut paths: Vec<PathBuf> = names.iter().map(|n| home.join(".jupyter").join(n)).collect();
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            for n in names {
                paths.push(win.join(".jupyter").join(n));
            }
        }
    }
    paths
}

fn kernel_dirs(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut dirs = vec![home.join(".local").join("share").join("jupyter").join("kernels")];
    match plat {
        Platform::MacOs => dirs.push(home.join("Library").join("Jupyter").join("kernels")),
        Platform::Windows => {
            if let Some(ad) = appdata() {
                dirs.push(ad.join("jupyter").join("kernels"));
            }
        }
        Platform::Wsl => {
            if let Some(win) = wsl_windows_home() {
                dirs.push(win.join("AppData").join("Roaming").join("jupyter").join("kernels"));
            }
        }
        Platform::Linux => {}
    }
    dirs
}
