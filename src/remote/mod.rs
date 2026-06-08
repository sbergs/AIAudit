//! Remote scanning support: SMB2/SCM-based PSExec-style executor + AD discovery.
//!
//! `inventory` is always available so the CLI can parse `--inventory` files even
//! in the default build. The transport, executor, and AD discovery require the
//! `remote` feature (which pulls in `ldap3`).

#[cfg(feature = "remote")]
pub mod inventory;

#[cfg(feature = "remote")]
pub mod ad;
#[cfg(feature = "remote")]
pub mod dcerpc;
#[cfg(feature = "remote")]
pub mod executor;
#[cfg(feature = "remote")]
pub mod scm;
#[cfg(feature = "remote")]
pub mod smb;
/// Authentication method for remote SMB2 connections.
#[derive(Debug, Clone, Default)]
pub enum AuthMethod {
    /// NTLMv2 — requires `--user` (DOMAIN\user or user@domain) and `--password`.
    #[default]
    Ntlm,
    /// Kerberos via the system GSSAPI ticket cache.
    /// Run `kinit user@DOMAIN.COM` before scanning; no password flag needed.
    /// Only available when built with `--features kerberos`.
    #[cfg(feature = "kerberos")]
    Kerberos,
}

/// Connection settings shared across hosts. Consumed by the remote executor.
#[derive(Debug, Clone, Default)]
pub struct RemoteConfig {
    pub user: Option<String>,
    pub password: Option<String>,
    pub auth: AuthMethod,
    pub port: Option<u16>,
    /// Path to the Windows exe to upload. Defaults to the current executable,
    /// which is wrong when the orchestrator runs on macOS/Linux — use `--remote-binary`.
    pub remote_binary: Option<std::path::PathBuf>,
    pub timeout_secs: u64,
}
