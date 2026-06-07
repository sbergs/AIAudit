//! Host inventory loading and parsing (requires `remote` feature).
#![cfg(feature = "remote")]

use std::path::Path;

#[derive(Debug, Clone)]
pub struct Host {
    pub hostname: String,
    pub user: Option<String>,
    pub port: u16,
    pub tags: Vec<String>,
}

impl Host {
    pub fn new(hostname: impl Into<String>) -> Self {
        Host {
            hostname: hostname.into(),
            user: None,
            port: 5985,
            tags: Vec::new(),
        }
    }
}

/// Parse `user@host:port` into a Host. Missing fields use defaults.
pub fn parse_host_str(s: &str) -> Host {
    let s = s.trim();
    let (user, rest) = match s.split_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, s),
    };
    let (hostname, port) = match rest.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (rest.to_string(), 5985),
        },
        None => (rest.to_string(), 5985),
    };
    Host {
        hostname,
        user,
        port,
        tags: Vec::new(),
    }
}

/// Load an inventory from a file. Detects format by extension/content:
/// JSON (array of objects or strings), CSV, or newline-delimited host strings.
/// YAML is parsed with a minimal `- host` / `hostname:` line reader.
pub fn load_inventory(path: &Path) -> anyhow::Result<Vec<Host>> {
    let content = std::fs::read_to_string(path)?;
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "json" => parse_json(&content),
        "csv" => Ok(parse_csv(&content)),
        "yml" | "yaml" => Ok(parse_yaml(&content)),
        _ => {
            // Heuristic: JSON if it starts with [ or {.
            let trimmed = content.trim_start();
            if trimmed.starts_with('[') || trimmed.starts_with('{') {
                parse_json(&content)
            } else {
                Ok(parse_text(&content))
            }
        }
    }
}

fn parse_json(content: &str) -> anyhow::Result<Vec<Host>> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    let arr = value
        .as_array()
        .cloned()
        .or_else(|| value.get("hosts").and_then(|h| h.as_array()).cloned())
        .ok_or_else(|| anyhow::anyhow!("inventory JSON must be an array or have a 'hosts' array"))?;

    let mut hosts = Vec::new();
    for item in arr {
        if let Some(s) = item.as_str() {
            hosts.push(parse_host_str(s));
        } else if let Some(obj) = item.as_object() {
            let hostname = obj
                .get("hostname")
                .or_else(|| obj.get("host"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("host object missing 'hostname'"))?;
            let mut host = Host::new(hostname);
            host.user = obj.get("user").and_then(|v| v.as_str()).map(String::from);
            if let Some(p) = obj.get("port").and_then(|v| v.as_u64()) {
                host.port = p as u16;
            }
            if let Some(tags) = obj.get("tags").and_then(|v| v.as_array()) {
                host.tags = tags.iter().filter_map(|t| t.as_str().map(String::from)).collect();
            }
            hosts.push(host);
        }
    }
    Ok(hosts)
}

fn parse_csv(content: &str) -> Vec<Host> {
    let mut hosts = Vec::new();
    let mut lines = content.lines();
    // Optional header row containing "hostname".
    let mut header: Vec<String> = Vec::new();
    if let Some(first) = lines.clone().next() {
        if first.to_ascii_lowercase().contains("host") {
            header = first.split(',').map(|s| s.trim().to_ascii_lowercase()).collect();
            lines.next();
        }
    }
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if header.is_empty() {
            hosts.push(parse_host_str(cols[0]));
        } else {
            let get = |name: &str| -> Option<&str> {
                header.iter().position(|h| h == name).and_then(|i| cols.get(i).copied())
            };
            let hostname = get("hostname").or_else(|| get("host")).unwrap_or(cols[0]);
            let mut host = Host::new(hostname);
            host.user = get("user").filter(|s| !s.is_empty()).map(String::from);
            if let Some(p) = get("port").and_then(|p| p.parse().ok()) {
                host.port = p;
            }
            hosts.push(host);
        }
    }
    hosts
}

fn parse_yaml(content: &str) -> Vec<Host> {
    // Minimal: lines like "- host" or "- hostname: foo".
    let mut hosts = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("- ") {
            let rest = rest.trim();
            if let Some((k, v)) = rest.split_once(':') {
                if k.trim() == "hostname" || k.trim() == "host" {
                    hosts.push(Host::new(v.trim().trim_matches('"')));
                }
            } else if !rest.is_empty() {
                hosts.push(parse_host_str(rest.trim_matches('"')));
            }
        }
    }
    hosts
}

fn parse_text(content: &str) -> Vec<Host> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_host_str)
        .collect()
}
