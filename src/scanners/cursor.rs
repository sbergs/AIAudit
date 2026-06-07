//! Cursor IDE MCP credential scanner.

use crate::mcp::scan_mcp_file;
use crate::platform::{self, appdata, home_dir, wsl_windows_home, xdg_config_dir, Platform};
use crate::scanner::{ScanResult, Scanner};
use std::path::PathBuf;

pub struct CursorScanner;

impl Scanner for CursorScanner {
    fn name(&self) -> &str {
        "Cursor IDE"
    }
    fn slug(&self) -> &str {
        "cursor"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for path in mcp_paths(plat) {
            let (findings, errors) = scan_mcp_file(&path, self.name(), show_secrets);
            result.findings.extend(findings);
            result.errors.extend(errors);
        }
        result
    }
}

fn mcp_paths(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut paths = vec![home.join(".cursor").join("mcp.json")];

    match plat {
        Platform::MacOs => paths.push(
            home.join("Library")
                .join("Application Support")
                .join("Cursor")
                .join("User")
                .join("globalStorage")
                .join("mcp.json"),
        ),
        Platform::Windows => {
            if let Some(ad) = appdata() {
                paths.push(ad.join("Cursor").join("User").join("globalStorage").join("mcp.json"));
            }
        }
        Platform::Linux | Platform::Wsl => {
            paths.push(
                xdg_config_dir()
                    .join("Cursor")
                    .join("User")
                    .join("globalStorage")
                    .join("mcp.json"),
            );
        }
    }

    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".cursor").join("mcp.json"));
        }
        if let Some(ad) = appdata() {
            paths.push(ad.join("Cursor").join("User").join("globalStorage").join("mcp.json"));
        }
    }
    paths
}
