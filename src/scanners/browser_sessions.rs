//! Browser session storage scanner.
//!
//! Detects the presence of browser session/storage databases that may hold AI
//! service tokens. These are encrypted/at-rest DBs, so findings are metadata
//! (storage type `EncryptedDb`, INFO/MEDIUM risk) rather than extracted secrets.

use crate::permissions::FileFacts;
use crate::platform::{self, appdata, home_dir, localappdata, Platform};
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult, Scanner, StorageType};
use std::path::PathBuf;

pub struct BrowserSessionsScanner;

impl Scanner for BrowserSessionsScanner {
    fn name(&self) -> &str {
        "Browser Sessions"
    }
    fn slug(&self) -> &str {
        "browser-sessions"
    }
    fn scan(&self, _show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for (browser, path) in candidate_stores(plat) {
            if path.exists() {
                let facts = FileFacts::gather(&path);
                result.findings.push(
                    CredentialFinding::new(
                        self.name(),
                        format!("session_store:{}", browser),
                        StorageType::EncryptedDb,
                        path.display().to_string(),
                        RiskLevel::Medium,
                    )
                    .with_perms(facts.permissions.clone(), facts.owner.clone())
                    .with_modified(facts.modified)
                    .with_notes(vec![
                        format!("{} session/local storage present", browser),
                        "May contain AI service session tokens/cookies".into(),
                    ]),
                );
            }
        }
        result
    }
}

fn candidate_stores(plat: Platform) -> Vec<(&'static str, PathBuf)> {
    let home = home_dir();
    let mut out: Vec<(&str, PathBuf)> = Vec::new();

    // Firefox profile storage.
    let firefox_root = match plat {
        Platform::Linux | Platform::Wsl => home.join(".mozilla").join("firefox"),
        Platform::MacOs => home.join("Library").join("Application Support").join("Firefox"),
        Platform::Windows => appdata()
            .unwrap_or_else(|| home.join("AppData").join("Roaming"))
            .join("Mozilla")
            .join("Firefox"),
    };
    if let Ok(entries) = std::fs::read_dir(firefox_root.join("Profiles")) {
        for e in entries.flatten() {
            let db = e.path().join("webappsstore.sqlite");
            if db.exists() {
                out.push(("Firefox", db));
            }
        }
    }

    // Chromium-family Local Storage.
    let chromium: Vec<(&str, PathBuf)> = match plat {
        Platform::Linux | Platform::Wsl => vec![
            ("Google Chrome", home.join(".config").join("google-chrome").join("Default").join("Local Storage")),
            ("Brave", home.join(".config").join("BraveSoftware").join("Brave-Browser").join("Default").join("Local Storage")),
            ("Chromium", home.join(".config").join("chromium").join("Default").join("Local Storage")),
            ("Microsoft Edge", home.join(".config").join("microsoft-edge").join("Default").join("Local Storage")),
        ],
        Platform::MacOs => {
            let base = home.join("Library").join("Application Support");
            vec![
                ("Google Chrome", base.join("Google").join("Chrome").join("Default").join("Local Storage")),
                ("Brave", base.join("BraveSoftware").join("Brave-Browser").join("Default").join("Local Storage")),
                ("Microsoft Edge", base.join("Microsoft Edge").join("Default").join("Local Storage")),
            ]
        }
        Platform::Windows => {
            let lad = localappdata().unwrap_or_else(|| home.join("AppData").join("Local"));
            vec![
                ("Google Chrome", lad.join("Google").join("Chrome").join("User Data").join("Default").join("Local Storage")),
                ("Microsoft Edge", lad.join("Microsoft").join("Edge").join("User Data").join("Default").join("Local Storage")),
                ("Brave", lad.join("BraveSoftware").join("Brave-Browser").join("User Data").join("Default").join("Local Storage")),
            ]
        }
    };
    out.extend(chromium);
    out
}
