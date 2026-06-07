//! Scanner for shell rc / profile / .env files.

use super::line_scan::scan_lines;
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner, StorageType};
use std::path::PathBuf;

pub struct ShellRcScanner;

impl Scanner for ShellRcScanner {
    fn name(&self) -> &str {
        "Shell RC Files"
    }
    fn slug(&self) -> &str {
        "shell-rc"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for path in rc_paths(plat) {
            scan_lines(&path, self.name(), StorageType::PlaintextFile, &mut result, show_secrets);
        }
        for path in env_paths(plat) {
            scan_lines(&path, self.name(), StorageType::PlaintextEnv, &mut result, show_secrets);
        }
        result
    }
}

fn rc_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".profile"),
        home.join(".zshrc"),
        home.join(".zprofile"),
        home.join(".zshenv"),
        home.join(".config").join("fish").join("config.fish"),
    ];
    paths.push(home.join("Documents").join("PowerShell").join("Microsoft.PowerShell_profile.ps1"));
    paths.push(home.join("Documents").join("WindowsPowerShell").join("Microsoft.PowerShell_profile.ps1"));
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join("Documents").join("PowerShell").join("Microsoft.PowerShell_profile.ps1"));
            paths.push(win.join("Documents").join("WindowsPowerShell").join("Microsoft.PowerShell_profile.ps1"));
        }
    }
    paths
}

fn env_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![
        home.join(".env"),
        home.join(".config").join(".env"),
        home.join(".docker").join(".env"),
        home.join(".config").join("fish").join(".env"),
        home.join(".local").join(".env"),
    ];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".env"));
        }
    }
    paths
}
