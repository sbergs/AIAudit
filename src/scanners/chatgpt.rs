//! ChatGPT Desktop credential scanner.

use super::json_scan::scan_json_tokens;
use crate::platform::{self, appdata, home_dir, Platform};
use crate::scanner::{ScanResult, Scanner};
use std::path::PathBuf;

pub struct ChatGptScanner;

impl Scanner for ChatGptScanner {
    fn name(&self) -> &str {
        "ChatGPT Desktop"
    }
    fn slug(&self) -> &str {
        "chatgpt"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        for dir in config_dirs(plat) {
            for fname in ["config.json", "auth.json", "session.json", "tokens.json"] {
                let path = dir.join(fname);
                scan_json_tokens(&path, self.name(), "chatgpt:", 10, &mut result, show_secrets);
            }
        }
        result
    }
}

fn config_dirs(plat: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut dirs = Vec::new();
    match plat {
        Platform::MacOs => {
            let base = home.join("Library").join("Application Support");
            dirs.push(base.join("ChatGPT"));
            dirs.push(base.join("com.openai.chat"));
        }
        Platform::Windows | Platform::Wsl => {
            if let Some(ad) = appdata() {
                dirs.push(ad.join("OpenAI").join("ChatGPT"));
                dirs.push(ad.join("com.openai.chat"));
            }
        }
        Platform::Linux => {}
    }
    dirs
}
