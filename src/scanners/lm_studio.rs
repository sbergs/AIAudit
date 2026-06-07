//! LM Studio scanner: config files and unauthenticated server exposure.

use super::json_scan::scan_json_tokens;
use super::line_scan::scan_lines;
use crate::platform::{self, appdata, home_dir, wsl_windows_home, xdg_config_dir, Platform};
use crate::remediation::hint_network_bind;
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult, Scanner, StorageType};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

pub struct LmStudioScanner;

impl Scanner for LmStudioScanner {
    fn name(&self) -> &str {
        "LM Studio"
    }
    fn slug(&self) -> &str {
        "lm-studio"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for base in config_dirs(plat) {
            scan_lines(&base.join(".env"), self.name(), StorageType::PlaintextEnv, &mut result, show_secrets);
            for fname in ["config.json", "settings.json"] {
                scan_json_tokens(&base.join(fname), self.name(), "config:", 10, &mut result, show_secrets);
            }
        }

        if let Ok(addr) = "127.0.0.1:1234".parse::<SocketAddr>() {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                result.findings.push(
                    CredentialFinding::new(self.name(), "network_exposure", StorageType::Unknown, "listening on 127.0.0.1:1234", RiskLevel::High)
                        .with_notes(vec![
                            "LM Studio local server is reachable".into(),
                            "The OpenAI-compatible server has no built-in authentication".into(),
                        ])
                        .with_remediation("Ensure the LM Studio server is not exposed beyond localhost", hint_network_bind("lm-studio", None, Some(1234))),
                );
            }
        }

        result
    }
}

fn config_dirs(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut dirs = Vec::new();
    match plat {
        Platform::MacOs => dirs.push(home.join("Library").join("Application Support").join("LM Studio")),
        Platform::Windows => {
            if let Some(ad) = appdata() {
                dirs.push(ad.join("LM Studio"));
            }
            dirs.push(home.join("AppData").join("Local").join("LM Studio"));
        }
        Platform::Linux => {
            dirs.push(xdg_config_dir().join("LM Studio"));
            dirs.push(home.join(".var").join("app").join("com.lmstudio.lmstudio").join("config").join("LM Studio"));
        }
        Platform::Wsl => {
            dirs.push(xdg_config_dir().join("LM Studio"));
            if let Some(ad) = appdata() {
                dirs.push(ad.join("LM Studio"));
            }
            if let Some(win) = wsl_windows_home() {
                dirs.push(win.join("AppData").join("Local").join("LM Studio"));
            }
        }
    }
    dirs
}
