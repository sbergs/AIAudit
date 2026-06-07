//! Structured, machine-readable remediation hints.
//!
//! Each variant serializes to a JSON object keyed by an `action` string so AI/MCP
//! consumers can act on it. We expose them as `serde_json::Value` to match the
//! `CredentialFinding::remediation_hint` field type.

use serde::Serialize;
use serde_json::{json, Value};

/// Known remediation actions. Serialized via `to_value`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RemediationHint {
    Chmod {
        args: Vec<String>,
    },
    MigrateToEnv {
        env_vars: Vec<String>,
        source: String,
    },
    ChangeConfigValue {
        target: String,
        new_value: Value,
        source: String,
    },
    RunCommand {
        shell: String,
        commands: Vec<String>,
    },
    UseCredentialHelper {
        tool: String,
        helper_options: Vec<String>,
    },
    RotateCredential {
        provider: String,
        description: String,
    },
    Manual {
        description: String,
        #[serde(flatten)]
        extra: Value,
    },
}

impl From<RemediationHint> for Value {
    fn from(h: RemediationHint) -> Value {
        serde_json::to_value(h).unwrap_or(Value::Null)
    }
}

pub fn hint_chmod(mode: &str, path: &str) -> Value {
    RemediationHint::Chmod {
        args: vec![mode.to_string(), path.to_string()],
    }
    .into()
}

pub fn hint_migrate_to_env(env_vars: Vec<String>, source: &str) -> Value {
    RemediationHint::MigrateToEnv {
        env_vars,
        source: source.to_string(),
    }
    .into()
}

#[allow(dead_code)]
pub fn hint_change_config_value(target: &str, new_value: Value, source: &str) -> Value {
    RemediationHint::ChangeConfigValue {
        target: target.to_string(),
        new_value,
        source: source.to_string(),
    }
    .into()
}

#[allow(dead_code)]
pub fn hint_run_command(commands: Vec<String>, shell: &str) -> Value {
    RemediationHint::RunCommand {
        shell: shell.to_string(),
        commands,
    }
    .into()
}

pub fn hint_use_credential_helper(tool: &str, helper_options: &[&str]) -> Value {
    RemediationHint::UseCredentialHelper {
        tool: tool.to_string(),
        helper_options: helper_options.iter().map(|s| s.to_string()).collect(),
    }
    .into()
}

#[allow(dead_code)]
pub fn hint_rotate_credential(provider: &str, description: &str) -> Value {
    RemediationHint::RotateCredential {
        provider: provider.to_string(),
        description: description.to_string(),
    }
    .into()
}

pub fn hint_manual(description: &str) -> Value {
    RemediationHint::Manual {
        description: description.to_string(),
        extra: json!({}),
    }
    .into()
}

pub fn hint_manual_with(description: &str, extra: Value) -> Value {
    RemediationHint::Manual {
        description: description.to_string(),
        extra,
    }
    .into()
}

/// Rebind a service from 0.0.0.0 to 127.0.0.1.
pub fn hint_network_bind(service: &str, path: Option<&str>, port: Option<u16>) -> Value {
    let mut v = json!({
        "action": "change_config_value",
        "target": "bind_address",
        "new_value": "127.0.0.1",
        "service": service,
    });
    if let Some(p) = path {
        v["source"] = json!(p);
    }
    if let Some(port) = port {
        v["port"] = json!(port);
    }
    v
}
