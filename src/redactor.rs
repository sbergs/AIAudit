//! Secret value masking and redaction.

use regex::Regex;
use std::sync::OnceLock;

/// Known credential prefixes and their display names, longest-first for matching.
pub const KNOWN_PREFIXES: &[(&str, &str)] = &[
    ("sk-ant-ort", "Anthropic Refresh"),
    ("sk-ant-oat", "Anthropic Access"),
    ("github_pat_", "GitHub PAT (fine-grained)"),
    ("sk-ant-", "Anthropic"),
    ("ghp_", "GitHub PAT (classic)"),
    ("gho_", "GitHub OAuth"),
    ("ghu_", "GitHub User-to-Server"),
    ("ghs_", "GitHub Server-to-Server"),
    ("xoxb-", "Slack Bot"),
    ("xoxp-", "Slack User"),
    ("xoxa-", "Slack App"),
    ("ya29.", "Google OAuth Access"),
    ("AKIA", "AWS Access Key"),
    ("AIza", "Google API Key"),
    ("sk-", "OpenAI/Generic"),
];

/// Mask a credential value, preserving any known prefix and the last 4 chars.
pub fn mask_value(value: &str, show_full: bool) -> String {
    if show_full {
        return value.to_string();
    }
    if value.is_empty() || value.chars().count() <= 8 {
        return "***REDACTED***".to_string();
    }

    let matched = KNOWN_PREFIXES
        .iter()
        .find(|(p, _)| value.starts_with(p))
        .map(|(p, _)| *p);

    let last4: String = value.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();

    if let Some(prefix) = matched {
        let plen = prefix.len();
        let total = value.len();
        let extra = std::cmp::min(4, total.saturating_sub(plen).saturating_sub(4));
        let start = if extra > 0 { &value[..plen + extra] } else { &value[..plen] };
        format!("{}...{}", start, last4)
    } else {
        let head: String = value.chars().take(6).collect();
        format!("{}...{}", head, last4)
    }
}

/// Identify a credential type by its prefix, if known.
pub fn identify_credential_type(value: &str) -> Option<&'static str> {
    KNOWN_PREFIXES
        .iter()
        .find(|(p, _)| value.starts_with(p))
        .map(|(_, name)| *name)
}

fn prefix_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let alt: Vec<String> = KNOWN_PREFIXES
            .iter()
            .map(|(p, _)| regex::escape(p))
            .collect();
        let pat = format!(
            r"(?:^|[^A-Za-z0-9_\-])((?:{})[A-Za-z0-9_\-./+=]{{16,}})",
            alt.join("|")
        );
        Regex::new(&pat).expect("valid prefix regex")
    })
}

fn context_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (
              (?:api[_-]?key|token|secret|password|passwd|auth[a-z_-]*|bearer)\s*[=:]\s*
            | export\s+[A-Z_][A-Z0-9_]*\s*=\s*
            | -H\s+["']?Authorization:\s*Bearer\s+
            | -H\s+["']?x-api-key:\s*
            | --api-key\s+
            | --token\s+
            )
            ["']?([A-Za-z0-9_\-./+=]{20,})["']?
            "#,
        )
        .expect("valid context regex")
    })
}

/// True if `line` contains a secret assignment pattern (key=value, export, Bearer header).
/// Used by line scanners to avoid duplicating the context regex.
pub fn line_matches_assignment(line: &str) -> bool {
    context_re().is_match(line)
}


/// Redact credential values found anywhere in a line of text.
pub fn redact_line(line: &str) -> String {
    // Pass 1: known-prefix tokens. Capture group 1 is the token; preserve the
    // boundary char that precedes it.
    let after_prefix = prefix_token_re().replace_all(line, |caps: &regex::Captures| {
        let full = &caps[0];
        let token = &caps[1];
        let boundary = &full[..full.len() - token.len()];
        format!("{}{}", boundary, mask_value(token, false))
    });

    // Pass 2: context-based assignments / headers.
    let after_context = context_re().replace_all(&after_prefix, |caps: &regex::Captures| {
        format!("{}{}", &caps[1], mask_value(&caps[2], false))
    });

    after_context.into_owned()
}
