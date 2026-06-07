//! Scanner for PowerShell PSReadLine history and profile scripts.

use super::line_scan::scan_lines;
use crate::platform::{self, appdata, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner, StorageType};
use std::path::PathBuf;

pub struct PowerShellScanner;

impl Scanner for PowerShellScanner {
    fn name(&self) -> &str {
        "PowerShell Logs"
    }
    fn slug(&self) -> &str {
        "powershell"
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
    let psreadline = |base: PathBuf| {
        base.join("Microsoft")
            .join("Windows")
            .join("PowerShell")
            .join("PSReadLine")
            .join("ConsoleHost_history.txt")
    };

    let mut paths = vec![
        home.join(".local").join("share").join("powershell").join("PSReadLine").join("ConsoleHost_history.txt"),
        home.join(".config").join("powershell").join("PSReadLine").join("ConsoleHost_history.txt"),
    ];

    if plat == Platform::Windows {
        if let Some(ad) = appdata() {
            paths.push(psreadline(ad));
        }
    }
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(psreadline(win.join("AppData").join("Roaming")));
        }
    }
    paths
}
