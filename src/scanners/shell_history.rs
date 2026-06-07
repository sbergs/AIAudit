//! Scanner for shell history files.

use super::line_scan::scan_lines;
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner, StorageType};
use std::path::PathBuf;

pub struct ShellHistoryScanner;

impl Scanner for ShellHistoryScanner {
    fn name(&self) -> &str {
        "Shell History"
    }
    fn slug(&self) -> &str {
        "shell-history"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for path in history_paths(plat) {
            scan_lines(&path, self.name(), StorageType::PlaintextFile, &mut result, show_secrets);
        }
        result
    }
}

fn history_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![
        home.join(".bash_history"),
        home.join(".zsh_history"),
        home.join(".zhistory"),
        home.join(".sh_history"),
        home.join(".history"),
        home.join(".local").join("share").join("fish").join("fish_history"),
    ];
    if let Ok(zdot) = std::env::var("ZDOTDIR") {
        paths.push(PathBuf::from(zdot).join(".zsh_history"));
    }
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".bash_history"));
        }
    }
    paths
}
