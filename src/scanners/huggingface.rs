//! Hugging Face CLI token scanner.

use super::plain_scan::scan_plain_token;
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner};
use std::path::PathBuf;

pub struct HuggingFaceScanner;

impl Scanner for HuggingFaceScanner {
    fn name(&self) -> &str {
        "Hugging Face CLI"
    }
    fn slug(&self) -> &str {
        "huggingface"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for path in paths(plat) {
            scan_plain_token(&path, self.name(), "hf_token", &mut result, show_secrets);
        }
        result
    }
}

fn paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![
        home.join(".cache").join("huggingface").join("token"),
        home.join(".huggingface").join("token"),
    ];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".cache").join("huggingface").join("token"));
            paths.push(win.join(".huggingface").join("token"));
        }
    }
    paths
}
