//! File permission analysis and risk assessment.

use crate::scanner::{RiskLevel, StorageType};
use chrono::{DateTime, Utc};
use std::path::Path;

/// Permission/ownership facts about a file, gathered in one stat call.
#[derive(Debug, Clone, Default)]
pub struct FileFacts {
    pub permissions: Option<String>,
    pub owner: Option<String>,
    pub modified: Option<DateTime<Utc>>,
    world_readable: bool,
    group_readable: bool,
    owner_only: bool,
}

impl FileFacts {
    pub fn gather(path: &Path) -> FileFacts {
        let mut facts = FileFacts {
            modified: get_file_mtime(path),
            ..Default::default()
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.permissions().mode() & 0o7777;
                facts.permissions = Some(format!("{:04o}", mode));
                facts.world_readable = mode & 0o004 != 0;
                facts.group_readable = mode & 0o040 != 0;
                facts.owner_only = matches!(mode & 0o777, 0o600 | 0o400);
                facts.owner = lookup_owner(meta.uid());
            }
        }

        #[cfg(not(unix))]
        {
            if let Ok(meta) = std::fs::metadata(path) {
                let ro = meta.permissions().readonly();
                facts.permissions = Some(if ro { "readonly".into() } else { "writable".into() });
                facts.owner_only = true; // best-effort on Windows
            }
        }

        facts
    }
}

#[cfg(unix)]
fn lookup_owner(uid: u32) -> Option<String> {
    // Parse /etc/passwd to map uid -> name without extra crates.
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _pw = fields.next();
        let uid_field = fields.next()?;
        if uid_field.parse::<u32>().ok() == Some(uid) {
            return Some(name.to_string());
        }
    }
    Some(uid.to_string())
}

pub fn get_file_mtime(path: &Path) -> Option<DateTime<Utc>> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    Some(DateTime::<Utc>::from(modified))
}

/// Human-readable staleness, e.g. "3 hours ago", "45 days ago".
pub fn describe_staleness(mtime: DateTime<Utc>) -> String {
    let now = Utc::now();
    let delta = now.signed_duration_since(mtime);
    let seconds = delta.num_seconds();
    if seconds < 60 {
        return "just now".to_string();
    }
    if seconds < 3600 {
        let mins = seconds / 60;
        return format!("{} minute{} ago", mins, plural(mins));
    }
    if seconds < 86400 {
        let hours = seconds / 3600;
        return format!("{} hour{} ago", hours, plural(hours));
    }
    let days = seconds / 86400;
    if days < 365 {
        return format!("{} day{} ago", days, plural(days));
    }
    let years = days / 365;
    format!("{} year{} ago", years, plural(years))
}

fn plural(n: i64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Translate an octal permission string into a human-readable description.
pub fn describe_permissions(perms: Option<&str>) -> String {
    let perms = match perms {
        Some(p) => p,
        None => return "unknown".to_string(),
    };
    let mode = match u32::from_str_radix(perms, 8) {
        Ok(m) => m,
        Err(_) => return "unknown".to_string(),
    };

    let group_r = mode & 0o040 != 0;
    let group_w = mode & 0o020 != 0;
    let other_r = mode & 0o004 != 0;
    let other_w = mode & 0o002 != 0;
    let other_x = mode & 0o001 != 0;

    let mut parts: Vec<&str> = Vec::new();
    if other_w {
        parts.push("world-writable");
    }
    if other_r {
        parts.push("world-readable");
    }
    if other_x && !other_r && !other_w {
        parts.push("world-executable");
    }
    if group_w && !other_w {
        parts.push("group-writable");
    }
    if group_r && !other_r {
        parts.push("group-readable");
    }
    if !group_r && !other_r {
        parts.push("owner-only");
    }
    if other_w {
        parts.push("DANGEROUS");
    }

    if parts.is_empty() {
        "owner-only".to_string()
    } else {
        parts.join(", ")
    }
}

/// Determine risk level from storage type and (optionally) file permissions.
pub fn assess_risk(storage: StorageType, facts: Option<&FileFacts>) -> RiskLevel {
    match storage {
        StorageType::EnvironmentVar
        | StorageType::Keychain
        | StorageType::CredentialManager
        | StorageType::EncryptedDb => RiskLevel::Medium,
        s if s.is_plaintext() => match facts {
            Some(f) if f.world_readable => RiskLevel::Critical,
            Some(f) if f.group_readable => RiskLevel::High,
            Some(f) if f.owner_only => RiskLevel::Medium,
            _ => RiskLevel::High,
        },
        _ => RiskLevel::Info,
    }
}
