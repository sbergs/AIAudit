//! Parallel remote host scanning via PSExec-style SMB2 + SCM service execution.
//!
//! Replaces the WinRM-based executor. Uses only std::net::TcpStream; no external
//! crates beyond those already in Cargo.toml.

#![cfg(feature = "remote")]

use super::inventory::Host;
use super::scm::Scm;
use super::smb::{SmbAuth, SmbSession};
use super::{AuthMethod, RemoteConfig};
use crate::scanner::ScanResult;
use rayon::prelude::*;

/// Scan all hosts in parallel. `on_progress` is invoked per host with its results.
pub fn scan_hosts_parallel(
    hosts: &[Host],
    config: &RemoteConfig,
    max_workers: usize,
    on_progress: impl Fn(&Host, &[ScanResult]) + Send + Sync,
) -> Vec<ScanResult> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(max_workers.max(1))
        .build();

    let run = |host: &Host| -> Vec<ScanResult> {
        let results = scan_one_host(host, config).unwrap_or_else(|e| {
            let mut r = ScanResult::error("remote", &format!("{}: {}", host.hostname, e));
            r.host = Some(host.hostname.clone());
            vec![r]
        });
        on_progress(host, &results);
        results
    };

    match pool {
        Ok(pool) => pool.install(|| hosts.par_iter().flat_map(run).collect()),
        Err(_) => hosts.par_iter().flat_map(run).collect(),
    }
}

/// PSExec-style remote scan:
///   1. SMB2 connect + auth (NTLMv2 or Kerberos)
///   2. Upload binary to ADMIN$\Temp\aiaudit.exe (chunked, 64 KB)
///   3. Create transient service via SCM, run it, wait for completion
///   4. Read output from ADMIN$\Temp\aiaudit_out.txt
///   5. Cleanup binary + output file
fn scan_one_host(host: &Host, config: &RemoteConfig) -> anyhow::Result<Vec<ScanResult>> {
    let auth = build_auth(config)?;
    let session = SmbSession::connect(&host.hostname, auth)?;

    // Connect to ADMIN$ (file upload) and IPC$ (named pipes / SCM)
    let admin_tree = session.connect_tree("ADMIN$")?;
    let ipc_tree = session.connect_tree("IPC$")?;

    // Upload the Windows binary — use --remote-binary if specified, else current exe
    let exe_path = config
        .remote_binary
        .clone()
        .map(Ok)
        .unwrap_or_else(std::env::current_exe)?;
    let bytes = std::fs::read(&exe_path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", exe_path.display(), e))?;
    session.write_file(admin_tree, r"Temp\aiaudit.exe", &bytes)?;

    // Run via SCM — output redirected to a temp file
    let binary_path =
        r"cmd /c C:\Windows\Temp\aiaudit.exe --json > C:\Windows\Temp\aiaudit_out.txt 2>&1";
    let svc_name = {
        let base = host.hostname.as_str();
        format!("aih_{}", &base[..base.len().min(8)])
    };

    let mut scm = Scm::open(&session, ipc_tree)?;
    scm.run_command(&session, &svc_name, binary_path)?;

    // Read output
    let output = session.read_file(admin_tree, r"Temp\aiaudit_out.txt")?;

    // Best-effort cleanup
    let _ = session.delete_file(admin_tree, r"Temp\aiaudit.exe");
    let _ = session.delete_file(admin_tree, r"Temp\aiaudit_out.txt");

    let json_str = String::from_utf8_lossy(&output);
    let report = extract_json(&json_str)
        .ok_or_else(|| anyhow::anyhow!("no JSON in output from {}", host.hostname))?;
    parse_report(&report, &host.hostname)
}

fn build_auth(config: &RemoteConfig) -> anyhow::Result<SmbAuth> {
    match &config.auth {
        AuthMethod::Ntlm => {
            let user = config.user.as_deref().unwrap_or_default();
            let password = config.password.as_deref().unwrap_or_default();
            let (domain, username) = split_domain_user(user);
            Ok(SmbAuth::Ntlm {
                user: username.to_string(),
                domain: domain.to_string(),
                password: password.to_string(),
            })
        }
        #[cfg(feature = "kerberos")]
        AuthMethod::Kerberos => Ok(SmbAuth::Kerberos {
            principal: config.user.as_deref().map(upn_from_user),
            password: config.password.clone(),
        }),
    }
}

/// Normalise a user string into UPN form for Kerberos (`user@DOMAIN.COM`).
/// Accepts `DOMAIN\user`, `user@domain`, or bare `user` (returned as-is).
/// The domain portion is uppercased because KDCs require uppercase realm names.
fn upn_from_user(user: &str) -> String {
    if let Some(pos) = user.find('\\') {
        let domain = &user[..pos];
        let username = &user[pos + 1..];
        format!("{}@{}", username, domain.to_uppercase())
    } else if user.contains('@') {
        // Already UPN — uppercase the realm portion.
        if let Some(at) = user.rfind('@') {
            format!("{}@{}", &user[..at], user[at + 1..].to_uppercase())
        } else {
            user.to_string()
        }
    } else {
        user.to_string()
    }
}

/// Split "DOMAIN\user" or "user@domain" into (domain, user).
/// Returns ("", user) if no domain separator is found.
fn split_domain_user(user: &str) -> (&str, &str) {
    if let Some(pos) = user.find('\\') {
        (&user[..pos], &user[pos + 1..])
    } else if let Some(pos) = user.find('@') {
        (&user[pos + 1..], &user[..pos])
    } else {
        ("", user)
    }
}

/// Pull the first complete JSON object out of mixed command output.
fn extract_json(output: &str) -> Option<String> {
    let start = output.find('{')?;
    let end = output.rfind('}')?;
    if end > start {
        Some(output[start..=end].to_string())
    } else {
        None
    }
}

/// Convert the remote JSON report into per-host ScanResults.
fn parse_report(json: &str, host: &str) -> anyhow::Result<Vec<ScanResult>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let mut result = ScanResult::new(format!("remote:{}", host), "windows");
    result.host = Some(host.to_string());

    if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
        for f in findings {
            if let Ok(mut finding) =
                serde_json::from_value::<crate::scanner::CredentialFinding>(f.clone())
            {
                finding.host = Some(host.to_string());
                result.findings.push(finding);
            }
        }
    }
    if let Some(errors) = value.get("errors").and_then(|e| e.as_array()) {
        for e in errors {
            if let Some(s) = e.as_str() {
                result.errors.push(s.to_string());
            }
        }
    }
    Ok(vec![result])
}
