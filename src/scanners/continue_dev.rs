//! Continue.dev config scanner (~/.continue/config.json|yaml).

use super::json_scan::scan_json_tokens;
use super::yaml_scan::scan_yaml;
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner};
use std::path::PathBuf;

pub struct ContinueDevScanner;

impl Scanner for ContinueDevScanner {
    fn name(&self) -> &str {
        "Continue.dev"
    }
    fn slug(&self) -> &str {
        "continue-dev"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        let (json_paths, yaml_paths) = paths(plat);
        for path in json_paths {
            scan_json_tokens(&path, self.name(), "config:", 8, &mut result, show_secrets);
        }
        for path in yaml_paths {
            scan_yaml(&path, self.name(), &mut result, show_secrets);
        }
        result
    }
}

fn paths(plat: Platform) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let home = home_dir();
    let mut json = vec![home.join(".continue").join("config.json")];
    let mut yaml = vec![home.join(".continue").join("config.yaml")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            json.push(win.join(".continue").join("config.json"));
            yaml.push(win.join(".continue").join("config.yaml"));
        }
    }
    (json, yaml)
}
