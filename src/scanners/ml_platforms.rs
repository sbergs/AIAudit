//! ML platform credential scanner (Replicate / Together / Groq).

use super::json_scan::scan_json_tokens;
use super::plain_scan::scan_plain_token;
use crate::platform::{self, appdata, home_dir, wsl_windows_home, Platform};
use crate::scanner::{ScanResult, Scanner};

pub struct MlPlatformsScanner;

impl Scanner for MlPlatformsScanner {
    fn name(&self) -> &str {
        "ML Platforms (Replicate/Together/Groq)"
    }
    fn slug(&self) -> &str {
        "ml-platforms"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());
        let home = home_dir();
        let win = if plat == Platform::Wsl { wsl_windows_home() } else { None };
        let ad = appdata();

        for (svc, plain_name, json_name, vendor) in [
            ("replicate", "auth", "config.json", "replicate"),
            ("together", "api_key", "config.json", "together"),
            ("groq", "api_key", "config.json", "groq"),
        ] {
            let dot = format!(".{}", svc);

            let mut plain = vec![home.join(&dot).join(plain_name)];
            let mut json = vec![home.join(&dot).join(json_name)];
            if let Some(w) = &win {
                plain.push(w.join(&dot).join(plain_name));
                json.push(w.join(&dot).join(json_name));
            }
            if let Some(a) = &ad {
                json.push(a.join(vendor).join(json_name));
            }

            for p in plain {
                scan_plain_token(&p, self.name(), &format!("{}_api_key", svc), &mut result, show_secrets);
            }
            for p in json {
                scan_json_tokens(&p, self.name(), &format!("{}:", svc), 8, &mut result, show_secrets);
            }
        }
        result
    }
}
