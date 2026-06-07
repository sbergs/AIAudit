//! Colored terminal table output.

use crate::permissions::{describe_permissions, describe_staleness};
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult};
use colored::{Color, Colorize};

fn risk_color(risk: RiskLevel) -> Color {
    match risk {
        RiskLevel::Critical => Color::Red,
        RiskLevel::High => Color::Yellow,
        RiskLevel::Medium => Color::TrueColor { r: 215, g: 135, b: 0 },
        RiskLevel::Low => Color::Green,
        RiskLevel::Info => Color::Cyan,
    }
}

const BANNER: &str = r#"+-+-+-+-+-+-+-+
|N|e|t|w|r|i|x|
+-+-+-+-+-+-+-+
    ___    ______  __                      __
   /   |  /  _/ / / /___  __  ______  ____/ /
  / /| |  / // /_/ / __ \/ / / / __ \/ __  /
 / ___ |_/ // __  / /_/ / /_/ / / / / /_/ /
/_/  |_/___/_/ /_/\____/\__,_/_/ /_/\__,_/

  AI Credential & Secrets Scanner
  For authorized use only. Use on systems you own or have permission to test."#;

pub fn print_banner(no_color: bool) {
    if no_color {
        println!("{}", BANNER);
    } else {
        println!("{}", BANNER.bold().blue());
    }
    println!();
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        let head: String = s.chars().take(width.saturating_sub(3)).collect();
        format!("{}...", head)
    }
}

/// Print all results as a table. When any result has a host, a Host column is added.
pub fn print_results(results: &[ScanResult], no_color: bool, verbose: bool) {
    let remote = super::is_remote(results);
    let findings = super::sorted_findings(results);
    let errors: Vec<&String> = results.iter().flat_map(|r| r.errors.iter()).collect();

    if findings.is_empty() {
        println!("No AI credentials found.");
        if verbose && !errors.is_empty() {
            println!("\nErrors:");
            for e in &errors {
                println!("  - {}", e);
            }
        }
        return;
    }

    let (cw_host, cw_tool, cw_type, cw_storage, cw_loc, cw_risk) = (18, 16, 22, 12, 35, 8);

    let header = if remote {
        format!(
            "{:<hw$} {:<tw$} {:<yw$} {:<sw$} {:<lw$} {:<rw$}",
            "Host", "Tool", "Credential Type", "Storage", "Location", "Risk",
            hw = cw_host, tw = cw_tool, yw = cw_type, sw = cw_storage, lw = cw_loc, rw = cw_risk
        )
    } else {
        format!(
            "{:<tw$} {:<yw$} {:<sw$} {:<lw$} {:<rw$}",
            "Tool", "Credential Type", "Storage", "Location", "Risk",
            tw = cw_tool, yw = cw_type, sw = cw_storage, lw = cw_loc, rw = cw_risk
        )
    };
    let sep = "-".repeat(header.len());

    println!("{}", sep);
    if no_color {
        println!("{}", header);
    } else {
        println!("{}", header.bold());
    }
    println!("{}", sep);

    for f in &findings {
        let risk_str = {
            let s = f.risk_level.to_string().to_uppercase();
            if no_color {
                s
            } else {
                s.color(risk_color(f.risk_level)).to_string()
            }
        };

        let row = if remote {
            format!(
                "{:<hw$} {:<tw$} {:<yw$} {:<sw$} {:<lw$} {}",
                truncate(f.host.as_deref().unwrap_or("-"), cw_host),
                truncate(&f.tool_name, cw_tool),
                truncate(f.credential_type.as_str(), cw_type),
                truncate(f.storage_type.as_str(), cw_storage),
                truncate(&f.location, cw_loc),
                risk_str,
                hw = cw_host, tw = cw_tool, yw = cw_type, sw = cw_storage, lw = cw_loc
            )
        } else {
            format!(
                "{:<tw$} {:<yw$} {:<sw$} {:<lw$} {}",
                truncate(&f.tool_name, cw_tool),
                truncate(f.credential_type.as_str(), cw_type),
                truncate(f.storage_type.as_str(), cw_storage),
                truncate(&f.location, cw_loc),
                risk_str,
                tw = cw_tool, yw = cw_type, sw = cw_storage, lw = cw_loc
            )
        };
        println!("{}", row);

        let indent = if remote { cw_host + cw_tool + 1 } else { cw_tool };

        if let Some(preview) = &f.value_preview {
            println!("{:>w$} Value: {}", "", preview, w = indent);
        }
        if verbose {
            print_verbose(f, indent, no_color);
        }
    }

    println!("{}", sep);
    print_summary(&findings, no_color);

    if verbose && !errors.is_empty() {
        println!("\nErrors ({}):", errors.len());
        for e in &errors {
            println!("  - {}", e);
        }
    }
}

fn print_verbose(f: &CredentialFinding, indent: usize, no_color: bool) {
    for note in &f.notes {
        println!("{:>w$} Note: {}", "", note, w = indent);
    }
    if let Some(perms) = &f.file_permissions {
        let desc = describe_permissions(Some(perms));
        println!(
            "{:>w$} Perms: {} ({}) Owner: {}",
            "",
            perms,
            desc,
            f.file_owner.as_deref().unwrap_or("N/A"),
            w = indent
        );
    }
    if let Some(m) = f.file_modified {
        println!(
            "{:>w$} Last modified: {} ({})",
            "",
            m.to_rfc3339(),
            describe_staleness(m),
            w = indent
        );
    }
    if let Some(rem) = &f.remediation {
        let fix = format!("Fix: {}", rem);
        if no_color {
            println!("{:>w$} {}", "", fix, w = indent);
        } else {
            println!("{:>w$} {}", "", fix.green(), w = indent);
        }
    }
}

fn print_summary(findings: &[&CredentialFinding], no_color: bool) {
    let mut parts = vec![format!("{} findings", findings.len())];
    for level in RiskLevel::ALL {
        let count = findings.iter().filter(|f| f.risk_level == level).count();
        if count > 0 {
            let label = format!("{} {}", count, level.to_string().to_uppercase());
            if no_color {
                parts.push(label);
            } else {
                parts.push(label.color(risk_color(level)).to_string());
            }
        }
    }
    println!("\nSummary: {}", parts.join(" | "));
}
