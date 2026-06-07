//! Scanner for AI-service network exposure via locally listening ports.

use crate::platform;
use crate::remediation::hint_network_bind;
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult, Scanner, StorageType};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub struct NetworkExposureScanner;

/// (port, service). Ports probed via a localhost TCP connect.
const AI_PORTS: &[(u16, &str)] = &[
    (11434, "Ollama"),
    (1234, "LM Studio"),
    (8888, "Jupyter Notebook/Lab"),
    (7860, "Gradio / text-generation-webui"),
    (8000, "vLLM"),
    (8080, "LocalAI"),
    (3000, "Open WebUI"),
    (8188, "ComfyUI"),
];

impl Scanner for NetworkExposureScanner {
    fn name(&self) -> &str {
        "AI Network Exposure"
    }
    fn slug(&self) -> &str {
        "network-exposure"
    }
    fn scan(&self, _show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        for (port, service) in AI_PORTS {
            let addr: SocketAddr = match format!("127.0.0.1:{}", port).parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                // A loopback service with no auth is HIGH; ports commonly exposed
                // to all interfaces (web UIs) are CRITICAL when reachable.
                let risk = match *port {
                    8888 | 7860 | 3000 | 8080 | 8188 => RiskLevel::Critical,
                    _ => RiskLevel::High,
                };
                result.findings.push(
                    CredentialFinding::new(
                        self.name(),
                        "network_exposure",
                        StorageType::Unknown,
                        format!("listening on 127.0.0.1:{}", port),
                        risk,
                    )
                    .with_preview(format!("127.0.0.1:{}", port))
                    .with_notes(vec![
                        format!("{} reachable on 127.0.0.1:{}", service, port),
                        "Most AI service web UIs have no built-in authentication".into(),
                        format!("Port {} detected as {}", port, service),
                    ])
                    .with_remediation(
                        format!("Ensure {} requires authentication or is firewalled", service),
                        hint_network_bind(service, None, Some(*port)),
                    ),
                );
            }
        }

        result
    }
}
