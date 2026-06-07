//! Scanner for AI-related environment variables.

use crate::platform;
use crate::redactor::{identify_credential_type, mask_value};
use crate::remediation::hint_manual_with;
use crate::scanner::{CredentialFinding, RiskLevel, ScanResult, Scanner, StorageType};
use serde_json::json;

pub struct EnvVarScanner;

/// (env name, description)
const AI_ENV_VARS: &[(&str, &str)] = &[
    ("ANTHROPIC_API_KEY", "Anthropic API key"),
    ("ANTHROPIC_AUTH_TOKEN", "Anthropic auth token (Bearer)"),
    ("CLAUDE_CODE_OAUTH_TOKEN", "Claude Code long-lived OAuth token"),
    ("CLAUDE_CODE_USE_BEDROCK", "Claude Code Bedrock flag (indicates AWS auth)"),
    ("CLAUDE_CODE_USE_VERTEX", "Claude Code Vertex flag (indicates GCP auth)"),
    ("CLAUDE_CODE_USE_FOUNDRY", "Claude Code Foundry flag"),
    ("OPENAI_API_KEY", "OpenAI API key"),
    ("OPENAI_ORG_ID", "OpenAI organization ID"),
    ("GEMINI_API_KEY", "Google Gemini API key"),
    ("GOOGLE_API_KEY", "Google API key"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "Google service account key file path"),
    ("GITHUB_TOKEN", "GitHub token"),
    ("GH_TOKEN", "GitHub CLI token"),
    ("GITHUB_PERSONAL_ACCESS_TOKEN", "GitHub personal access token"),
    ("COPILOT_GITHUB_TOKEN", "GitHub Copilot token"),
    ("AWS_ACCESS_KEY_ID", "AWS access key ID"),
    ("AWS_SECRET_ACCESS_KEY", "AWS secret access key"),
    ("AWS_SESSION_TOKEN", "AWS session token"),
    ("AWS_PROFILE", "AWS profile name"),
    ("ADO_MCP_AUTH_TOKEN", "Azure DevOps MCP auth token"),
    ("AZURE_OPENAI_API_KEY", "Azure OpenAI API key"),
    ("AZURE_OPENAI_ENDPOINT", "Azure OpenAI endpoint"),
    ("HUGGING_FACE_HUB_TOKEN", "Hugging Face Hub token"),
    ("HF_TOKEN", "Hugging Face token"),
    ("COHERE_API_KEY", "Cohere API key"),
    ("REPLICATE_API_TOKEN", "Replicate API token"),
    ("MISTRAL_API_KEY", "Mistral AI API key"),
    ("TOGETHER_API_KEY", "Together AI API key"),
    ("GROQ_API_KEY", "Groq API key"),
    ("FIREWORKS_API_KEY", "Fireworks AI API key"),
    ("PERPLEXITY_API_KEY", "Perplexity API key"),
    ("XAI_API_KEY", "xAI/Grok API key"),
    ("DEEPSEEK_API_KEY", "DeepSeek API key"),
    ("OLLAMA_API_KEY", "Ollama API key (auth proxy)"),
    ("LM_STUDIO_API_KEY", "LM Studio API key"),
];

const FLAG_VARS: &[&str] = &[
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "AWS_PROFILE",
];

impl Scanner for EnvVarScanner {
    fn name(&self) -> &str {
        "Environment Variables"
    }
    fn slug(&self) -> &str {
        "envvars"
    }
    fn scan(&self, show_secrets: bool) -> ScanResult {
        let plat = platform::detect();
        let mut result = ScanResult::new(self.name(), plat.as_str());

        let rem_hint = || {
            hint_manual_with(
                "Use a secret manager instead of environment variables",
                json!({ "suggested_tools": ["1Password CLI", "doppler", "vault"] }),
            )
        };

        for (var, desc) in AI_ENV_VARS {
            let value = match std::env::var(var) {
                Ok(v) if !v.is_empty() => v,
                _ => continue,
            };

            if FLAG_VARS.contains(var) {
                result.findings.push(
                    CredentialFinding::new(
                        self.name(),
                        *desc,
                        StorageType::EnvironmentVar,
                        format!("${}", var),
                        RiskLevel::Info,
                    )
                    .with_preview(&value)
                    .with_notes(vec!["Configuration flag, not a secret".into()]),
                );
                continue;
            }

            if *var == "GOOGLE_APPLICATION_CREDENTIALS" {
                result.findings.push(
                    CredentialFinding::new(
                        self.name(),
                        *desc,
                        StorageType::EnvironmentVar,
                        format!("${}", var),
                        RiskLevel::Medium,
                    )
                    .with_preview(&value)
                    .with_notes(vec![format!("Points to service account key file: {}", value)])
                    .with_remediation(
                        "Use a secret manager instead of environment variables",
                        rem_hint(),
                    ),
                );
                continue;
            }

            let mut notes = Vec::new();
            if let Some(t) = identify_credential_type(&value) {
                notes.push(format!("Identified as: {}", t));
            }

            result.findings.push(
                CredentialFinding::new(
                    self.name(),
                    *desc,
                    StorageType::EnvironmentVar,
                    format!("${}", var),
                    RiskLevel::Medium,
                )
                .with_preview(mask_value(&value, show_secrets))
                .with_raw(if show_secrets { Some(value) } else { None })
                .with_notes(notes)
                .with_remediation(
                    "Use a secret manager instead of environment variables",
                    rem_hint(),
                ),
            );
        }

        result
    }
}
