//! Amazon Q / AWS credential scanner (~/.aws/credentials, SSO cache).

use super::json_scan::scan_json_tokens;
use super::line_scan::scan_lines;
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner, StorageType};
use std::path::PathBuf;

pub struct AmazonQScanner;

impl Scanner for AmazonQScanner {
    fn name(&self) -> &str {
        "Amazon Q / AWS"
    }
    fn slug(&self) -> &str {
        "amazon-q"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for path in credentials_paths(plat) {
            scan_lines(&path, self.name(), StorageType::PlaintextIni, &mut result, show_secrets);
        }
        for dir in sso_cache_dirs(plat) {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.extension().map(|x| x == "json").unwrap_or(false) {
                        scan_json_tokens(&p, self.name(), "sso:", 8, &mut result, show_secrets);
                    }
                }
            }
        }
        result
    }
}

fn credentials_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![home.join(".aws").join("credentials")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".aws").join("credentials"));
        }
    }
    paths
}

fn sso_cache_dirs(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut dirs = vec![home.join(".aws").join("sso").join("cache")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            dirs.push(win.join(".aws").join("sso").join("cache"));
        }
    }
    dirs
}
