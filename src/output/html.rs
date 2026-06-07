//! Self-contained dark-theme HTML report.

use crate::scanner::{CredentialFinding, RiskLevel, ScanResult};
use std::io::Write;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn risk_class(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Critical => "critical",
        RiskLevel::High => "high",
        RiskLevel::Medium => "medium",
        RiskLevel::Low => "low",
        RiskLevel::Info => "info",
    }
}

const CSS: &str = r#"
:root { color-scheme: dark; }
body { background:#0f1115; color:#e6e6e6; font-family:-apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:2rem; }
h1 { margin:0 0 .25rem; }
.subtitle { color:#8b94a3; margin-bottom:1.5rem; }
.summary { display:flex; gap:.75rem; flex-wrap:wrap; margin-bottom:1.5rem; }
.pill { padding:.4rem .8rem; border-radius:999px; font-weight:600; font-size:.85rem; }
table { border-collapse:collapse; width:100%; font-size:.9rem; }
th,td { text-align:left; padding:.55rem .7rem; border-bottom:1px solid #232733; vertical-align:top; }
th { color:#9aa4b2; text-transform:uppercase; font-size:.72rem; letter-spacing:.05em; }
td.loc { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; max-width:30rem; }
.risk { font-weight:700; }
.critical { color:#ff5c5c; }
.high { color:#ffb454; }
.medium { color:#e8a33d; }
.low { color:#5cd67a; }
.info { color:#4fc3f7; }
tr.critical td:first-child { border-left:3px solid #ff5c5c; }
tr.high td:first-child { border-left:3px solid #ffb454; }
tr.medium td:first-child { border-left:3px solid #e8a33d; }
tr.low td:first-child { border-left:3px solid #5cd67a; }
tr.info td:first-child { border-left:3px solid #4fc3f7; }
"#;

/// Write the HTML report to `writer`.
pub fn write_html(results: &[ScanResult], mut writer: impl Write) -> anyhow::Result<()> {
    let remote = super::is_remote(results);
    let findings = super::sorted_findings(results);

    let mut out = String::new();
    out.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    out.push_str("<title>AIHound Report</title><style>");
    out.push_str(CSS);
    out.push_str("</style></head><body>");
    out.push_str("<h1>AIHound Report</h1>");
    out.push_str(&format!(
        "<div class=\"subtitle\">Generated {} &middot; {} findings</div>",
        esc(&chrono::Utc::now().to_rfc3339()),
        findings.len()
    ));

    // Summary pills.
    out.push_str("<div class=\"summary\">");
    for level in RiskLevel::ALL {
        let count = findings.iter().filter(|f| f.risk_level == level).count();
        if count > 0 {
            out.push_str(&format!(
                "<span class=\"pill {}\">{} {}</span>",
                risk_class(level),
                count,
                level.to_string().to_uppercase()
            ));
        }
    }
    out.push_str("</div>");

    // Table.
    out.push_str("<table><thead><tr>");
    if remote {
        out.push_str("<th>Host</th>");
    }
    out.push_str("<th>Tool</th><th>Type</th><th>Storage</th><th>Location</th><th>Risk</th></tr></thead><tbody>");

    for f in &findings {
        out.push_str(&row_html(f, remote));
    }
    out.push_str("</tbody></table></body></html>");

    writer.write_all(out.as_bytes())?;
    Ok(())
}

fn row_html(f: &CredentialFinding, remote: bool) -> String {
    let cls = risk_class(f.risk_level);
    let mut row = format!("<tr class=\"{}\">", cls);
    if remote {
        row.push_str(&format!("<td>{}</td>", esc(f.host.as_deref().unwrap_or("-"))));
    }
    row.push_str(&format!("<td>{}</td>", esc(&f.tool_name)));
    row.push_str(&format!("<td>{}</td>", esc(f.credential_type.as_str())));
    row.push_str(&format!("<td>{}</td>", esc(f.storage_type.as_str())));
    row.push_str(&format!("<td class=\"loc\">{}</td>", esc(&f.location)));
    row.push_str(&format!(
        "<td class=\"risk {}\">{}</td>",
        cls,
        f.risk_level.to_string().to_uppercase()
    ));
    row.push_str("</tr>");
    row
}
