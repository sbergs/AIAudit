//! Ollama scanner: env config and unauthenticated API exposure.

use crate::platform;
use crate::redactor::mask_value;
use crate::remediation::{hint_change_config_value, hint_manual, hint_network_bind};
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult, Scanner, StorageType};
use serde_json::json;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub struct OllamaScanner;

const ENV_VARS: &[(&str, &str)] = &[
    ("OLLAMA_HOST", "Ollama host/bind address"),
    ("OLLAMA_ORIGINS", "Ollama CORS origins"),
    ("OLLAMA_API_KEY", "Ollama API key (auth proxy)"),
    ("OLLAMA_MODELS", "Ollama models directory"),
];

impl Scanner for OllamaScanner {
    fn name(&self) -> &str {
        "Ollama"
    }
    fn slug(&self) -> &str {
        "ollama"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for (var, desc) in ENV_VARS {
            let value = match std::env::var(var) {
                Ok(v) if !v.is_empty() => v,
                _ => continue,
            };
            if *var == "OLLAMA_HOST" && value.contains("0.0.0.0") {
                result.findings.push(
                    CredentialFinding::new(self.name(), "network_binding", StorageType::EnvironmentVar, format!("${}", var), RiskLevel::High)
                        .with_preview(&value)
                        .with_notes(vec![
                            "Ollama API bound to all interfaces (0.0.0.0)".into(),
                            "No built-in authentication — any network device can access the API".into(),
                        ])
                        .with_remediation("Bind to 127.0.0.1 instead of 0.0.0.0", hint_network_bind("ollama", None, Some(11434))),
                );
                continue;
            }
            if *var == "OLLAMA_ORIGINS" && value == "*" {
                result.findings.push(
                    CredentialFinding::new(self.name(), "cors_config", StorageType::EnvironmentVar, format!("${}", var), RiskLevel::Medium)
                        .with_preview(&value)
                        .with_notes(vec!["Wildcard CORS — any website can make requests to Ollama API".into()])
                        .with_remediation(
                            "Restrict CORS origins",
                            hint_change_config_value("OLLAMA_ORIGINS", json!("https://your-allowed-origin.example"), &format!("${}", var)),
                        ),
                );
                continue;
            }
            if *var == "OLLAMA_API_KEY" {
                result.findings.push(
                    CredentialFinding::new(self.name(), "api_key", StorageType::EnvironmentVar, format!("${}", var), RiskLevel::Medium)
                        .with_preview(mask_value(&value, show_secrets))
                        .with_raw(if show_secrets { Some(value.clone()) } else { None })
                        .with_notes(vec!["Ollama API key (likely for auth proxy)".into()])
                        .with_remediation("Use environment variables securely", hint_manual("Use environment variables securely")),
                );
                continue;
            }
            result.findings.push(
                CredentialFinding::new(self.name(), *desc, StorageType::EnvironmentVar, format!("${}", var), RiskLevel::Info)
                    .with_preview(&value)
                    .with_notes(vec!["Configuration flag".into()]),
            );
        }

        // Network exposure: probe localhost API.
        if let Ok(addr) = "127.0.0.1:11434".parse::<SocketAddr>() {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                result.findings.push(
                    CredentialFinding::new(self.name(), "network_exposure", StorageType::Unknown, "listening on 127.0.0.1:11434", RiskLevel::High)
                        .with_notes(vec![
                            "Ollama API is currently listening".into(),
                            "No built-in authentication — local processes can run inference".into(),
                        ])
                        .with_remediation("Ensure Ollama is not exposed beyond localhost", hint_network_bind("ollama", None, Some(11434))),
                );
            }
        }

        result
    }
}
