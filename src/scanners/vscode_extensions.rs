//! VS Code extension globalStorage credential scanner.

use super::json_scan::scan_json_tokens;
use crate::platform::{self, appdata, home_dir, wsl_windows_home, xdg_config_dir, Platform};
use crate::scanner::{ScanResult, Scanner};
use std::path::PathBuf;

pub struct VsCodeExtensionsScanner;

impl Scanner for VsCodeExtensionsScanner {
    fn name(&self) -> &str {
        "VS Code Extensions"
    }
    fn slug(&self) -> &str {
        "vscode-extensions"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for root in storage_roots(plat) {
            let entries = match std::fs::read_dir(&root) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let dir = entry.path();
                if !dir.is_dir() {
                    continue;
                }
                // Look at common JSON config files inside each extension's storage.
                for fname in ["hosts.json", "config.json", "state.json", "auth.json", "storage.json"] {
                    let path = dir.join(fname);
                    let ext = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    scan_json_tokens(&path, self.name(), &format!("{}:", ext), 16, &mut result, show_secrets);
                }
            }
        }
        result
    }
}

fn storage_roots(plat: Platform) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    match plat {
        Platform::Linux => roots.push(xdg_config_dir().join("Code").join("User").join("globalStorage")),
        Platform::MacOs => roots.push(
            home_dir()
                .join("Library")
                .join("Application Support")
                .join("Code")
                .join("User")
                .join("globalStorage"),
        ),
        Platform::Windows => {
            if let Some(ad) = appdata() {
                roots.push(ad.join("Code").join("User").join("globalStorage"));
            }
        }
        Platform::Wsl => {
            roots.push(xdg_config_dir().join("Code").join("User").join("globalStorage"));
            if let Some(ad) = appdata() {
                roots.push(ad.join("Code").join("User").join("globalStorage"));
            }
            if let Some(win) = wsl_windows_home() {
                roots.push(
                    win.join("AppData")
                        .join("Roaming")
                        .join("Code")
                        .join("User")
                        .join("globalStorage"),
                );
            }
        }
    }
    roots
}
