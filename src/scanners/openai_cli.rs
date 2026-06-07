//! OpenAI / Codex CLI credential scanner.

use super::json_scan::scan_json_tokens;
use super::plain_scan::scan_plain_token;
use crate::platform::{self, appdata, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner};
use std::path::PathBuf;

pub struct OpenAiCliScanner;

impl Scanner for OpenAiCliScanner {
    fn name(&self) -> &str {
        "OpenAI/Codex CLI"
    }
    fn slug(&self) -> &str {
        "openai-cli"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for path in plain_paths(plat) {
            scan_plain_token(&path, self.name(), "api_key", &mut result, show_secrets);
        }
        for path in json_paths(plat) {
            scan_json_tokens(&path, self.name(), "auth:", 8, &mut result, show_secrets);
        }
        result
    }
}

fn plain_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![home.join(".openai").join("api_key")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".openai").join("api_key"));
        }
    }
    if let Some(ad) = appdata() {
        paths.push(ad.join("OpenAI").join("api_key"));
    }
    paths
}

fn json_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![
        home.join(".openai").join("auth.json"),
        home.join(".codex").join("auth.json"),
    ];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".openai").join("auth.json"));
            paths.push(win.join(".codex").join("auth.json"));
        }
    }
    if let Some(ad) = appdata() {
        paths.push(ad.join("OpenAI").join("auth.json"));
    }
    paths
}
