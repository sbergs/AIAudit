//! Claude Desktop MCP config scanner.

use crate::mcp::scan_mcp_file;
use crate::platform::{self, appdata, home_dir, xdg_config_dir, Platform};
use crate::scanner::{ScanResult, Scanner};
use std::path::PathBuf;

pub struct ClaudeDesktopScanner;

const CONFIG: &str = "claude_desktop_config.json";

impl Scanner for ClaudeDesktopScanner {
    fn name(&self) -> &str {
        "Claude Desktop"
    }
    fn slug(&self) -> &str {
        "claude-desktop"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for path in config_paths(plat) {
            let (findings, errors) = scan_mcp_file(&path, self.name(), show_secrets);
            result.findings.extend(findings);
            result.errors.extend(errors);
        }
        result
    }
}

fn config_paths(plat: Platform) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match plat {
        Platform::MacOs => paths.push(
            home_dir()
                .join("Library")
                .join("Application Support")
                .join("Claude")
                .join(CONFIG),
        ),
        Platform::Windows => {
            if let Some(ad) = appdata() {
                paths.push(ad.join("Claude").join(CONFIG));
            }
        }
        Platform::Linux | Platform::Wsl => {
            paths.push(xdg_config_dir().join("Claude").join(CONFIG));
        }
    }
    if plat == Platform::Wsl {
        if let Some(ad) = appdata() {
            paths.push(ad.join("Claude").join(CONFIG));
        }
    }
    paths
}
