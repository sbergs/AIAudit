//! Scanner for persistent environment definitions (pam_environment, environment.d,
//! LaunchAgents, /etc/environment).

use super::line_scan::scan_lines;
use crate::platform::{self, home_dir, Platform};
use crate::scanner::{ScanResult, Scanner, StorageType};
use std::path::PathBuf;

pub struct PersistentEnvScanner;

impl Scanner for PersistentEnvScanner {
    fn name(&self) -> &str {
        "Persistent Environment"
    }
    fn slug(&self) -> &str {
        "persistent-env"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        let home = home_dir();

        let mut paths: Vec<PathBuf> = vec![
            home.join(".pam_environment"),
            PathBuf::from("/etc/environment"),
        ];

        // environment.d *.conf files
        let env_d = home.join(".config").join("environment.d");
        if let Ok(entries) = std::fs::read_dir(&env_d) {
            for e in entries.flatten() {
                if e.path().extension().map(|x| x == "conf").unwrap_or(false) {
                    paths.push(e.path());
                }
            }
        }

        // macOS LaunchAgents plists
        if plat == Platform::MacOs {
            let agents = home.join("Library").join("LaunchAgents");
            if let Ok(entries) = std::fs::read_dir(&agents) {
                for e in entries.flatten() {
                    if e.path().extension().map(|x| x == "plist").unwrap_or(false) {
                        paths.push(e.path());
                    }
                }
            }
        }

        for path in paths {
            scan_lines(&path, self.name(), StorageType::PlaintextEnv, &mut result, show_secrets);
        }
        result
    }
}
