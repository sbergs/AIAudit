//! Gemini CLI / GCloud credential scanner.

use super::json_scan::scan_json_tokens;
use super::line_scan::scan_lines;
use crate::platform::{self, appdata, home_dir, wsl_windows_home, xdg_config_dir, Platform};
use crate::scanner::{ScanResult, Scanner, StorageType};
use std::path::PathBuf;

pub struct GeminiScanner;

impl Scanner for GeminiScanner {
    fn name(&self) -> &str {
        "Gemini CLI / GCloud"
    }
    fn slug(&self) -> &str {
        "gemini"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for path in env_paths(plat) {
            scan_lines(&path, self.name(), StorageType::PlaintextEnv, &mut result, show_secrets);
        }
        for path in gcloud_paths(plat) {
            scan_json_tokens(&path, self.name(), "gcloud:", 8, &mut result, show_secrets);
        }
        result
    }
}

fn env_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![home.join(".gemini").join(".env"), home.join(".env")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".gemini").join(".env"));
            paths.push(win.join(".env"));
        }
    }
    paths
}

fn gcloud_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let cred = "application_default_credentials.json";
    let mut paths = Vec::new();
    match plat {
        Platform::Linux | Platform::Wsl => {
            paths.push(xdg_config_dir().join("gcloud").join(cred));
        }
        Platform::MacOs => {
            paths.push(home.join(".config").join("gcloud").join(cred));
        }
        Platform::Windows => {
            if let Some(ad) = appdata() {
                paths.push(ad.join("gcloud").join(cred));
            }
        }
    }
    if plat == Platform::Wsl {
        if let Some(ad) = appdata() {
            paths.push(ad.join("gcloud").join(cred));
        }
    }
    paths
}
