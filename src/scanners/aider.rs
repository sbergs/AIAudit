//! Aider config scanner (~/.aider.conf.yml).

use super::yaml_scan::scan_yaml;
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner};
use std::path::PathBuf;

pub struct AiderScanner;

impl Scanner for AiderScanner {
    fn name(&self) -> &str {
        "Aider"
    }
    fn slug(&self) -> &str {
        "aider"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for path in paths(plat) {
            scan_yaml(&path, self.name(), &mut result, show_secrets);
        }
        result
    }
}

fn paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![
        home.join(".aider.conf.yml"),
        home.join(".aider.conf.yaml"),
    ];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".aider.conf.yml"));
            paths.push(win.join(".aider.conf.yaml"));
        }
    }
    paths
}
