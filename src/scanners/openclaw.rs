//! OpenClaw scanner: agent auth-profiles, credentials, secrets, env, oauth.

use super::json_scan::scan_json_tokens;
use super::line_scan::scan_lines;
use crate::platform::{self, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner, StorageType};
use std::path::PathBuf;

pub struct OpenClawScanner;

impl Scanner for OpenClawScanner {
    fn name(&self) -> &str {
        "OpenClaw"
    }
    fn slug(&self) -> &str {
        "openclaw"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for base in bases(plat) {
            self.scan_base(&base, &mut result, show_secrets);
        }
        result
    }
}

impl OpenClawScanner {
    fn scan_base(&self, base: &std::path::Path, result: &mut ScanResult, show_secrets: bool) {
        if !base.exists() {
            return;
        }

        // Per-agent auth profiles
        let agents = base.join("agents");
        if let Ok(entries) = std::fs::read_dir(&agents) {
            for e in entries.flatten() {
                let auth = e.path().join("agent").join("auth-profiles.json");
                scan_json_tokens(&auth, self.name(), "auth_profile:", 8, result, show_secrets);
            }
        }

        // WhatsApp creds
        let wa = base.join("credentials").join("whatsapp");
        if let Ok(entries) = std::fs::read_dir(&wa) {
            for e in entries.flatten() {
                let creds = e.path().join("creds.json");
                scan_json_tokens(&creds, self.name(), "whatsapp:", 8, result, show_secrets);
            }
        }

        // Flat config / secret files
        for fname in ["secrets.json", "openclaw.json"] {
            scan_json_tokens(&base.join(fname), self.name(), "config:", 8, result, show_secrets);
        }
        scan_json_tokens(&base.join("credentials").join("oauth.json"), self.name(), "oauth:", 8, result, show_secrets);

        // .env file
        scan_lines(&base.join(".env"), self.name(), StorageType::PlaintextEnv, result, show_secrets);
    }
}

fn bases(plat: Platform) -> Vec<PathBuf> {
    let mut paths = vec![home_dir().join(".openclaw")];
    if plat == Platform::Wsl {
        if let Some(win) = wsl_windows_home() {
            paths.push(win.join(".openclaw"));
        }
    }
    paths
}
