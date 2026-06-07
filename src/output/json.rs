//! JSON report output.

use crate::scanner::{RiskLevel, ScanResult};
use serde_json::{json, Map, Value};
use std::io::Write;

/// Write the full JSON report to `writer`.
pub fn write_json(results: &[ScanResult], mut writer: impl Write) -> anyhow::Result<()> {
    let findings: Vec<&crate::scanner::CredentialFinding> =
        results.iter().flat_map(|r| r.findings.iter()).collect();
    let errors: Vec<&String> = results.iter().flat_map(|r| r.errors.iter()).collect();

    let mut by_risk = Map::new();
    for level in RiskLevel::ALL {
        let count = findings.iter().filter(|f| f.risk_level == level).count();
        by_risk.insert(level.to_string(), json!(count));
    }

    let mut hosts: Vec<String> = results
        .iter()
        .filter_map(|r| r.host.clone())
        .collect();
    hosts.sort();
    hosts.dedup();

    let platform = results
        .iter()
        .map(|r| r.platform.clone())
        .find(|p| !p.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let report = json!({
        "scan_metadata": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "platform": platform,
            "version": env!("CARGO_PKG_VERSION"),
            "hosts": hosts,
        },
        "findings": findings.iter().map(|f| serde_json::to_value(f).unwrap_or(Value::Null)).collect::<Vec<_>>(),
        "errors": errors,
        "summary": {
            "total_findings": findings.len(),
            "by_risk": by_risk,
        },
    });

    serde_json::to_writer_pretty(&mut writer, &report)?;
    writer.write_all(b"\n")?;
    Ok(())
}
