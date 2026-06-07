//! Cline (VS Code extension) MCP settings scanner.

use crate::mcp::scan_mcp_file;
use crate::platform::{self, appdata, home_dir, xdg_config_dir, Platform};
use crate::scanner::{ScanResult, Scanner};
use std::path::PathBuf;

pub struct ClineScanner;

const EXTENSION_ID: &str = "saoudrizwan.claude-dev";
const SETTINGS_FILE: &str = "settings/cline_mcp_settings.json";

impl Scanner for ClineScanner {
    fn name(&self) -> &str {
        "Cline (VS Code)"
    }
    fn slug(&self) -> &str {
        "cline"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for path in settings_paths(plat) {
            let (findings, errors) = scan_mcp_file(&path, self.name(), show_secrets);
            result.findings.extend(findings);
            result.errors.extend(errors);
        }
        result
    }
}

fn settings_paths(plat: Platform) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let rel = |base: PathBuf| base.join(EXTENSION_ID).join(SETTINGS_FILE);

    match plat {
        Platform::MacOs => paths.push(rel(home_dir()
            .join("Library")
            .join("Application Support")
            .join("Code")
            .join("User")
            .join("globalStorage"))),
        Platform::Windows => {
            if let Some(ad) = appdata() {
                paths.push(rel(ad.join("Code").join("User").join("globalStorage")));
            }
        }
        Platform::Linux | Platform::Wsl => {
            paths.push(rel(xdg_config_dir()
                .join("Code")
                .join("User")
                .join("globalStorage")));
        }
    }

    if plat == Platform::Wsl {
        if let Some(ad) = appdata() {
            paths.push(rel(ad.join("Code").join("User").join("globalStorage")));
        }
    }
    paths
}
