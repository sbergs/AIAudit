//! Output formatters.

pub mod html;
pub mod json;
pub mod table;

use crate::scanner::ScanResult;

/// Flatten findings from all results in risk order (most severe first).
pub fn sorted_findings(results: &[ScanResult]) -> Vec<&crate::scanner::CredentialFinding> {
    let mut findings: Vec<&crate::scanner::CredentialFinding> =
        results.iter().flat_map(|r| r.findings.iter()).collect();
    findings.sort_by_key(|f| f.risk_level);
    findings
}

/// True if any result carries a host (i.e. this is a remote scan).
pub fn is_remote(results: &[ScanResult]) -> bool {
    results.iter().any(|r| r.host.is_some())
        || results.iter().any(|r| r.findings.iter().any(|f| f.host.is_some()))
}
