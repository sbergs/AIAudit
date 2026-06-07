//! Core scanner trait and shared data model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

/// A validated credential type label. Use the factory methods for well-known
/// types; construct ad-hoc ones via `CredentialType::new("...")`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialType(String);

impl CredentialType {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }

    pub fn oauth_token() -> Self { Self::new("oauth_access_token") }
    pub fn api_key() -> Self { Self::new("api_key") }
    pub fn git_credential() -> Self { Self::new("git_credential") }
    pub fn mcp_env(key: &str) -> Self { Self::new(format!("mcp_env:{}", key)) }
    pub fn mcp_header(key: &str) -> Self { Self::new(format!("mcp_header:{}", key)) }
    pub fn env_var(name: &str) -> Self { Self::new(format!("env_var:{}", name)) }
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}
impl From<&str> for CredentialType {
    fn from(s: &str) -> Self { Self::new(s) }
}
impl From<String> for CredentialType {
    fn from(s: String) -> Self { Self(s) }
}
impl AsRef<str> for CredentialType {
    fn as_ref(&self) -> &str { &self.0 }
}

/// Risk level of a finding. Ordering is most-severe-first so `Ord` sorts naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "critical",
            RiskLevel::High => "high",
            RiskLevel::Medium => "medium",
            RiskLevel::Low => "low",
            RiskLevel::Info => "info",
        }
    }

    pub const ALL: [RiskLevel; 5] = [
        RiskLevel::Critical,
        RiskLevel::High,
        RiskLevel::Medium,
        RiskLevel::Low,
        RiskLevel::Info,
    ];
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a credential is stored on disk / in the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageType {
    PlaintextJson,
    PlaintextYaml,
    PlaintextEnv,
    PlaintextIni,
    PlaintextFile,
    Keychain,
    CredentialManager,
    EncryptedDb,
    EnvironmentVar,
    Unknown,
}

impl StorageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageType::PlaintextJson => "plaintext_json",
            StorageType::PlaintextYaml => "plaintext_yaml",
            StorageType::PlaintextEnv => "plaintext_env",
            StorageType::PlaintextIni => "plaintext_ini",
            StorageType::PlaintextFile => "plaintext_file",
            StorageType::Keychain => "keychain",
            StorageType::CredentialManager => "credman",
            StorageType::EncryptedDb => "encrypted_db",
            StorageType::EnvironmentVar => "env_var",
            StorageType::Unknown => "unknown",
        }
    }

    /// True if this is any plaintext-on-disk storage type.
    pub fn is_plaintext(&self) -> bool {
        matches!(
            self,
            StorageType::PlaintextJson
                | StorageType::PlaintextYaml
                | StorageType::PlaintextEnv
                | StorageType::PlaintextIni
                | StorageType::PlaintextFile
        )
    }
}

impl fmt::Display for StorageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single discovered credential or security-relevant artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialFinding {
    pub tool_name: String,
    pub credential_type: CredentialType,
    pub storage_type: StorageType,
    pub location: String,
    pub exists: bool,
    pub risk_level: RiskLevel,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_preview: Option<String>,

    /// Raw secret value — never serialized, zeroed on drop.
    #[serde(skip)]
    pub raw_value: Option<Zeroizing<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_permissions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_modified: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_hint: Option<serde_json::Value>,

    /// Hostname when produced by a remote scan; local scans leave this None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

impl CredentialFinding {
    /// Construct a finding with the required fields; chain `.with_*` for the rest.
    pub fn new(
        tool_name: impl Into<String>,
        credential_type: impl Into<CredentialType>,
        storage_type: StorageType,
        location: impl Into<String>,
        risk_level: RiskLevel,
    ) -> Self {
        CredentialFinding {
            tool_name: tool_name.into(),
            credential_type: credential_type.into(),
            storage_type,
            location: location.into(),
            exists: true,
            risk_level,
            value_preview: None,
            raw_value: None,
            file_permissions: None,
            file_owner: None,
            expiry: None,
            notes: Vec::new(),
            file_modified: None,
            remediation: None,
            remediation_hint: None,
            host: None,
        }
    }

    pub fn with_preview(mut self, preview: impl Into<String>) -> Self {
        self.value_preview = Some(preview.into());
        self
    }

    pub fn with_raw(mut self, raw: Option<String>) -> Self {
        self.raw_value = raw.map(Zeroizing::new);
        self
    }

    pub fn with_perms(mut self, perms: Option<String>, owner: Option<String>) -> Self {
        self.file_permissions = perms;
        self.file_owner = owner;
        self
    }

    pub fn with_modified(mut self, modified: Option<DateTime<Utc>>) -> Self {
        self.file_modified = modified;
        self
    }

    pub fn with_expiry(mut self, expiry: Option<DateTime<Utc>>) -> Self {
        self.expiry = expiry;
        self
    }

    pub fn with_notes(mut self, notes: Vec<String>) -> Self {
        self.notes = notes;
        self
    }

    pub fn push_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    pub fn with_remediation(
        mut self,
        remediation: impl Into<String>,
        hint: serde_json::Value,
    ) -> Self {
        self.remediation = Some(remediation.into());
        self.remediation_hint = Some(hint);
        self
    }
}

/// The output of running one scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanner_name: String,
    pub platform: String,
    #[serde(default)]
    pub findings: Vec<CredentialFinding>,
    #[serde(default)]
    pub errors: Vec<String>,
    pub scan_time: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

impl ScanResult {
    pub fn new(scanner_name: impl Into<String>, platform: impl Into<String>) -> Self {
        ScanResult {
            scanner_name: scanner_name.into(),
            platform: platform.into(),
            findings: Vec::new(),
            errors: Vec::new(),
            scan_time: 0.0,
            host: None,
        }
    }

    pub fn error(scanner_name: &str, message: &str) -> Self {
        ScanResult {
            scanner_name: scanner_name.to_string(),
            platform: String::new(),
            findings: Vec::new(),
            errors: vec![message.to_string()],
            scan_time: 0.0,
            host: None,
        }
    }
}

/// A credential scanner. Object-safe so scanners live in `Vec<Box<dyn Scanner>>`.
pub trait Scanner: Send + Sync {
    /// Human-readable name.
    fn name(&self) -> &str;

    /// CLI-friendly slug (e.g. `claude-code`).
    fn slug(&self) -> &str;

    /// Whether this scanner applies to the current platform.
    fn is_applicable(&self) -> bool {
        true
    }

    /// Perform the scan.
    fn scan(&self, show_secrets: bool) -> ScanResult;

    /// Run with timing and panic isolation so one bad scanner can't kill the run.
    fn run(&self, show_secrets: bool) -> ScanResult {
        let start = std::time::Instant::now();
        let mut r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.scan(show_secrets)
        }))
        .unwrap_or_else(|payload| {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                format!("scanner panicked: {}", s)
            } else if let Some(s) = payload.downcast_ref::<String>() {
                format!("scanner panicked: {}", s)
            } else {
                "scanner panicked (no message)".to_string()
            };
            ScanResult::error(self.name(), &msg)
        });
        r.scan_time = start.elapsed().as_secs_f64();
        r
    }
}
