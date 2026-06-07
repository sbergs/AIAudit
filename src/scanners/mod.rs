//! Scanner registry.

use crate::scanner::Scanner;

// Shared helpers.
mod json_scan;
mod line_scan;
mod plain_scan;
mod util;
mod yaml_scan;

// Individual scanners.
mod aider;
mod amazon_q;
mod browser_sessions;
mod chatgpt;
mod claude_code;
mod claude_desktop;
mod claude_sessions;
mod cline;
mod continue_dev;
mod cursor;
mod docker;
mod envvars;
mod gemini;
mod git_credentials;
mod github_copilot;
mod huggingface;
mod jupyter;
mod lm_studio;
mod ml_platforms;
mod network_exposure;
mod ollama;
mod openai_cli;
mod openclaw;
mod persistent_env;
mod powershell;
mod shell_history;
mod shell_rc;
mod vscode_extensions;
mod windsurf;

/// Construct every scanner. Order roughly groups related tools.
pub fn all_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(claude_code::ClaudeCodeScanner),
        Box::new(claude_desktop::ClaudeDesktopScanner),
        Box::new(claude_sessions::ClaudeSessionsScanner),
        Box::new(cursor::CursorScanner),
        Box::new(windsurf::WindsurfScanner),
        Box::new(github_copilot::GitHubCopilotScanner),
        Box::new(aider::AiderScanner),
        Box::new(cline::ClineScanner),
        Box::new(continue_dev::ContinueDevScanner),
        Box::new(chatgpt::ChatGptScanner),
        Box::new(gemini::GeminiScanner),
        Box::new(amazon_q::AmazonQScanner),
        Box::new(huggingface::HuggingFaceScanner),
        Box::new(jupyter::JupyterScanner),
        Box::new(lm_studio::LmStudioScanner),
        Box::new(ollama::OllamaScanner),
        Box::new(openai_cli::OpenAiCliScanner),
        Box::new(openclaw::OpenClawScanner),
        Box::new(ml_platforms::MlPlatformsScanner),
        Box::new(docker::DockerScanner),
        Box::new(git_credentials::GitCredentialsScanner),
        Box::new(envvars::EnvVarScanner),
        Box::new(shell_history::ShellHistoryScanner),
        Box::new(shell_rc::ShellRcScanner),
        Box::new(persistent_env::PersistentEnvScanner),
        Box::new(powershell::PowerShellScanner),
        Box::new(vscode_extensions::VsCodeExtensionsScanner),
        Box::new(network_exposure::NetworkExposureScanner),
        Box::new(browser_sessions::BrowserSessionsScanner),
    ]
}
