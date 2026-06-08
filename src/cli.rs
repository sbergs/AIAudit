//! Command-line interface and mode routing.

use crate::output::{html, json, table};
use crate::platform;
use crate::scanner::{RiskLevel, ScanResult, Scanner};
use crate::scanners::all_scanners;
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "aiaudit", about = "AI Credential & Secrets Scanner", version)]
pub struct Cli {
    #[command(flatten)]
    pub scan: ScanArgs,
    #[command(flatten)]
    pub output: OutputArgs,
    #[command(flatten)]
    pub remote: RemoteArgs,
    #[command(flatten)]
    pub watch: WatchArgs,
}

#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// Show actual credential values (USE WITH CAUTION; requires a TTY).
    #[arg(long)]
    pub show_secrets: bool,

    /// Only scan specific tools (use slugs from --list-tools).
    #[arg(long, num_args = 1.., value_name = "SLUG")]
    pub tools: Vec<String>,

    /// List all available scanners and exit.
    #[arg(long)]
    pub list_tools: bool,

    /// Show extra detail (notes, permissions, remediation).
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

#[derive(clap::Args, Debug)]
pub struct OutputArgs {
    /// Output results as JSON to stdout.
    #[arg(long)]
    pub json: bool,

    /// Write a JSON report to this file.
    #[arg(long, value_name = "PATH")]
    pub json_file: Option<PathBuf>,

    /// Write an HTML report to this file.
    #[arg(long, value_name = "PATH")]
    pub html_file: Option<PathBuf>,

    /// Disable colored output.
    #[arg(long)]
    pub no_color: bool,
}

#[derive(clap::Args, Debug)]
pub struct RemoteArgs {
    /// Remote Windows host(s) to scan (hostname or IP).
    #[arg(long, num_args = 1.., value_name = "HOST")]
    pub remote: Vec<String>,

    /// Load hosts from an inventory file (YAML/JSON/CSV/text).
    #[arg(long, value_name = "FILE")]
    pub inventory: Option<PathBuf>,

    /// Active Directory server FQDN for host discovery.
    #[arg(long, value_name = "FQDN")]
    pub ad_server: Option<String>,

    /// AD base DN for the search.
    #[arg(long, value_name = "DN")]
    pub ad_base_dn: Option<String>,

    /// Username for NTLM auth: DOMAIN\user or user@domain.
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,

    /// Password for NTLM auth.
    #[arg(long, value_name = "PASSWORD")]
    pub password: Option<String>,

    /// Use Kerberos auth from the system ticket cache instead of NTLM.
    /// Run `kinit user@DOMAIN.COM` first. Requires build with --features kerberos.
    #[cfg(feature = "kerberos")]
    #[arg(long)]
    pub kerberos: bool,

    /// SMB port (default 445).
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,

    /// Path to the Windows exe to upload when scanning from a non-Windows host.
    #[arg(long, value_name = "PATH")]
    pub remote_binary: Option<PathBuf>,

    /// Maximum parallel hosts.
    #[arg(long, default_value_t = 8, value_name = "N")]
    pub parallel: usize,

    /// Per-host timeout in seconds.
    #[arg(long, default_value_t = 120, value_name = "SECONDS")]
    pub remote_timeout: u64,
}

#[derive(clap::Args, Debug)]
pub struct WatchArgs {
    /// Run continuously, re-scanning on an interval (Ctrl+C to stop).
    #[arg(long)]
    pub watch: bool,

    /// Polling interval in seconds.
    #[arg(long, default_value_t = 30.0, value_name = "SECONDS")]
    pub interval: f64,
}

/// Entry point called from `main`.
pub fn run() -> anyhow::Result<i32> {
    let cli = Cli::parse();

    if cli.output.no_color {
        colored::control::set_override(false);
    }

    let scanners = all_scanners();

    if cli.scan.list_tools {
        println!("Available scanners:");
        for s in &scanners {
            let applicable = if s.is_applicable() {
                "yes"
            } else {
                "no (not applicable on this platform)"
            };
            println!("  {:<20} {:<38} Applicable: {}", s.slug(), s.name(), applicable);
        }
        return Ok(0);
    }

    // --show-secrets gate.
    let show_secrets = if cli.scan.show_secrets {
        if !io::stdin().is_terminal() {
            eprintln!("ERROR: --show-secrets requires an interactive terminal.");
            return Ok(1);
        }
        eprintln!("--show-secrets will display raw credential values. Use only on your own machine.");
        eprint!("Type 'YES' to confirm: ");
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin().read_line(&mut line).ok();
        if line.trim() != "YES" {
            println!("Aborted.");
            return Ok(1);
        }
        true
    } else {
        false
    };

    // Remote mode takes over.
    if !cli.remote.remote.is_empty() || cli.remote.inventory.is_some() || cli.remote.ad_server.is_some() {
        return run_remote(&cli);
    }

    // Filter scanners by --tools and applicability.
    let selected: Vec<&dyn Scanner> = scanners
        .iter()
        .map(|s| s.as_ref())
        .filter(|s| cli.scan.tools.is_empty() || cli.scan.tools.iter().any(|t| t == s.slug()))
        .filter(|s| s.is_applicable())
        .collect();

    if selected.is_empty() {
        eprintln!("No scanners matched. Use --list-tools to see available scanners.");
        return Ok(1);
    }

    if cli.watch.watch {
        return run_watch(&selected, &cli, show_secrets);
    }

    if !cli.output.json {
        table::print_banner(cli.output.no_color);
        let plat = platform::detect();
        println!("Platform: {}", plat.as_str());
        if plat == platform::Platform::Wsl {
            println!("WSL detected - scanning both Linux and Windows credential paths\n");
        } else {
            println!();
        }
    }

    let results = run_scanners(&selected, show_secrets);
    emit_output(&results, &cli)?;
    Ok(0)
}

fn run_scanners(scanners: &[&dyn Scanner], show_secrets: bool) -> Vec<ScanResult> {
    use rayon::prelude::*;
    scanners
        .par_iter()
        .map(|s| s.run(show_secrets))
        .collect()
}

fn emit_output(results: &[ScanResult], cli: &Cli) -> anyhow::Result<()> {
    if cli.output.json {
        json::write_json(results, io::stdout().lock())?;
    } else {
        table::print_results(results, cli.output.no_color, cli.scan.verbose);
    }

    if let Some(path) = &cli.output.json_file {
        let file = create_output_file(path)?;
        json::write_json(results, file)?;
        if !cli.output.json {
            println!("\nJSON report written to: {}", path.display());
        }
    }

    if let Some(path) = &cli.output.html_file {
        let file = create_output_file(path)?;
        html::write_html(results, file)?;
        if !cli.output.json {
            println!("HTML report written to: {}", path.display());
        }
    }

    Ok(())
}

fn create_output_file(path: &std::path::Path) -> anyhow::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(std::fs::File::create(path)?)
}

fn run_watch(scanners: &[&dyn Scanner], cli: &Cli, show_secrets: bool) -> anyhow::Result<i32> {
    use std::collections::HashSet;
    use std::time::Duration;

    if !cli.output.json {
        table::print_banner(cli.output.no_color);
        println!(
            "Watch mode: interval={}s, scanners={}. Press Ctrl+C to stop.\n",
            cli.watch.interval as u64,
            scanners.len()
        );
    }

    let mut seen: HashSet<String> = HashSet::new();
    loop {
        let results = run_scanners(scanners, show_secrets);
        for f in results.iter().flat_map(|r| r.findings.iter()) {
            let key = format!("{}|{}|{}", f.tool_name, f.credential_type, f.location);
            if seen.insert(key) {
                let risk = f.risk_level.to_string().to_uppercase();
                let line = format!(
                    "[{}] {} {} - {} ({})",
                    risk, f.tool_name, f.credential_type, f.location, f.risk_level
                );
                let _ = &risk;
                if cli.output.no_color || f.risk_level > RiskLevel::High {
                    println!("{}", line);
                } else {
                    use colored::Colorize;
                    println!("{}", line.yellow());
                }
            }
        }
        std::thread::sleep(Duration::from_secs_f64(cli.watch.interval.max(1.0)));
    }
}

#[cfg(feature = "remote")]
fn run_remote(cli: &Cli) -> anyhow::Result<i32> {
    use crate::remote::executor::scan_hosts_parallel;
    use crate::remote::inventory::{load_inventory, parse_host_str, Host};
    use crate::remote::{AuthMethod, RemoteConfig};

    let mut hosts: Vec<Host> = Vec::new();
    for s in &cli.remote.remote {
        hosts.push(parse_host_str(s));
    }
    if let Some(inv) = &cli.remote.inventory {
        hosts.extend(load_inventory(inv)?);
    }
    if let Some(server) = &cli.remote.ad_server {
        let base = cli
            .remote
            .ad_base_dn
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--ad-base-dn is required with --ad-server"))?;
        hosts.extend(crate::remote::ad::discover_hosts(
            server,
            base,
            cli.remote.user.as_deref(),
            cli.remote.password.as_deref(),
        )?);
    }

    if hosts.is_empty() {
        eprintln!("No remote hosts specified.");
        return Ok(1);
    }

    #[cfg(feature = "kerberos")]
    let auth = if cli.remote.kerberos {
        AuthMethod::Kerberos
    } else {
        AuthMethod::Ntlm
    };
    #[cfg(not(feature = "kerberos"))]
    let auth = AuthMethod::Ntlm;

    let config = RemoteConfig {
        user: cli.remote.user.clone(),
        password: cli.remote.password.clone(),
        auth,
        port: cli.remote.port,
        remote_binary: cli.remote.remote_binary.clone(),
        timeout_secs: cli.remote.remote_timeout,
    };

    if !cli.output.json {
        println!("Remote scan: {} host(s)\n", hosts.len());
    }

    let results = scan_hosts_parallel(&hosts, &config, cli.remote.parallel, |host, _| {
        if !cli.output.json {
            eprintln!("  scanned {}", host.hostname);
        }
    });

    emit_output(&results, cli)?;
    Ok(0)
}

#[cfg(not(feature = "remote"))]
fn run_remote(_cli: &Cli) -> anyhow::Result<i32> {
    eprintln!("Remote scanning requires the 'remote' feature: build with --features remote");
    Ok(1)
}
