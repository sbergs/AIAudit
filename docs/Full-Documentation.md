# AIAudit

**AI Credential & Secrets Scanner**

AIAudit scans your system for credentials, secrets, and tokens stored by popular AI desktop applications and coding assistants. It checks config files, credential stores, MCP server configurations, and environment variables — then reports what it finds with risk-rated output.

This is a security research tool. Credentials are **redacted by default** so output is safe to share in reports and screenshots.

## What It Finds

AIAudit doesn't just look for API keys. It scans for:

- **OAuth access & refresh tokens** (Claude, Copilot, ChatGPT)
- **API keys** (OpenAI, Anthropic, Google, AWS, Hugging Face, Replicate, Together, Groq, etc.)
- **MCP server secrets** — inline tokens, auth headers, and credentials embedded in MCP configurations
- **AWS credentials** — access keys, secret keys, session tokens, SSO cache
- **Google Cloud ADC** — application default credentials, service account keys
- **Docker registry credentials** — base64-encoded auth blobs in `~/.docker/config.json`
- **Git credential stores** — plaintext `~/.git-credentials`, embedded tokens in gitconfig
- **Jupyter server configs** — unauthenticated tokens, empty passwords, kernel env secrets
- **VS Code extension secrets** — tokens stored in extension globalStorage beyond Copilot/Cline
- **Browser AI sessions** — Firefox localStorage for claude.ai, chatgpt.com, gemini, etc.
- **Shell history** — bash, zsh, fish history files scanned for pasted API keys and tokens
- **PowerShell history** — API keys and tokens pasted into PSReadLine history or transcripts
- **Shell RC files** — `.bashrc`, `.zshrc`, fish config, PowerShell profiles, `.env` files with hardcoded `export VAR=secret` patterns
- **Persistent environment stores** — `/etc/environment`, `/etc/profile.d/`, `~/.pam_environment`, systemd `environment.d`, macOS LaunchAgent plists, Windows registry (`HKCU\Environment`, `HKLM\...\Environment`)
- **Active Claude sessions** — detects running Claude Code processes, live OAuth tokens, tmux/screen sessions hosting Claude, SSH-originated sessions, and Claude MCP servers on `0.0.0.0`
- **Local AI server exposure** — detects Ollama, LM Studio, Jupyter, Gradio, vLLM, LocalAI, Open WebUI, ComfyUI listening on all interfaces without authentication
- **Environment variables** — 35+ known AI-related env vars
- **Plaintext config files** — `.env` files, JSON configs with hardcoded secrets

Every finding includes **actionable remediation guidance** and **file staleness** (when the credential was last modified) in verbose mode.

## Supported Tools

**29 scanners** covering AI assistants, CLI tools, developer tools, and infrastructure:

### AI Assistants & Desktop Apps
| Tool | What's Scanned |
|---|---|
| **Claude Code CLI** | `~/.claude/.credentials.json`, `~/.claude.json` MCP config, Keychain |
| **Claude Desktop** | `claude_desktop_config.json`, MCP server env vars & headers |
| **ChatGPT Desktop** | App data directories (macOS & Windows) |

### AI Coding Assistants & IDEs
| Tool | What's Scanned |
|---|---|
| **GitHub Copilot** | Keychain/Credential Manager, `~/.copilot/config.json`, VS Code storage, `gh` CLI hosts.yml |
| **Cursor IDE** | `~/.cursor/mcp.json`, app config directories |
| **Continue.dev** | `~/.continue/config.json` (plaintext API keys) |
| **Cline** | `cline_mcp_settings.json` (plaintext MCP creds) |
| **Windsurf** | `~/.codeium/windsurf/` config and MCP settings |
| **Aider** | `~/.aider.conf.yml` provider API keys |
| **VS Code Extensions** | Extension globalStorage tokens (AWS Toolkit, GitLens, Thunder Client, etc.) |

### AI CLIs & Platform Tools
| Tool | What's Scanned |
|---|---|
| **OpenAI / Codex CLI** | `~/.openai/api_key`, `auth.json`, `~/.codex/` configs |
| **Hugging Face CLI** | `~/.cache/huggingface/token`, `~/.huggingface/token` |
| **Gemini CLI / GCloud** | `.env` files, application default credentials |
| **Amazon Q / AWS** | `~/.aws/credentials`, SSO cache tokens |
| **Replicate / Together / Groq** | `~/.replicate/auth`, `~/.together/`, `~/.groq/` configs |
| **OpenClaw** | `~/.openclaw/` auth profiles, channel creds, gateway tokens, `.env`, legacy OAuth |

### Local AI Servers & Network Exposure
| Tool | What's Scanned |
|---|---|
| **Ollama** | `~/.ollama/`, env vars, systemd service, network exposure (port 11434) |
| **LM Studio** | App config dirs, HF tokens, `.env` files, network exposure (port 1234) |
| **Jupyter** | Notebook/server configs (`.py` + `.json`), kernel env secrets, empty-token detection |
| **AI Network Exposure** | Detects Jupyter (8888), Gradio (7860), vLLM (8000), LocalAI (8080), Open WebUI (3000), ComfyUI (8188) bound to `0.0.0.0` |

### Shell & History
| Tool | What's Scanned |
|---|---|
| **Shell History** | `~/.bash_history`, `~/.zsh_history`, fish history — two-pass regex (known-prefix + context-based) |
| **PowerShell Logs** | PSReadLine `ConsoleHost_history.txt`, transcripts — detects tokens typed or pasted at the command line |
| **Shell RC Files** | `.bashrc`, `.zshrc`, `.zprofile`, fish `config.fish`, PowerShell profiles, `.env` files — scans `export VAR=secret` patterns |
| **Persistent Environment** | `/etc/environment`, `/etc/profile.d/*.sh`, `~/.pam_environment`, systemd `environment.d`, macOS LaunchAgents, Windows registry |

### Active Sessions & Runtime
| Tool | What's Scanned |
|---|---|
| **Claude Sessions** | Running `claude` processes (local + SSH-originated), `~/.claude/sessions/` files, live OAuth tokens, tmux/screen sessions hosting Claude, MCP servers on `0.0.0.0` |

### Developer & Infrastructure
| Tool | What's Scanned |
|---|---|
| **Docker** | `~/.docker/config.json` — base64 auth blobs, identity tokens, credential helpers |
| **Git Credentials** | `~/.git-credentials`, `~/.gitconfig` embedded tokens |
| **Browser Sessions** | Firefox localStorage for AI domains (claude.ai, chatgpt.com, gemini, perplexity, etc.); Chromium stub |
| **Environment Variables** | 35+ AI-related env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.) |

## Platform Support

| Platform | Status |
|---|---|
| **Linux** | Full support |
| **macOS** | Full support (includes Keychain queries) |
| **Windows** | Full support (includes Credential Manager) |
| **WSL** | Full support — scans **both** Linux paths and Windows paths via `/mnt/c/` |

---

<br>

# Installation

AIAudit is a Rust binary. Build it with `cargo`:

## Prerequisites

- [Rust toolchain](https://rustup.rs/) 1.75+

## Build

```bash
git clone https://github.com/sbergs/AIAudit.git
cd AIAudit

# Local scanning only (default)
cargo build --release

# With remote scanning (SMB2 + AD host discovery)
cargo build --release --features remote

# With remote scanning + Kerberos authentication (macOS/Linux only)
cargo build --release --features kerberos
```

The binary is at `./target/release/aiaudit` (or `aiaudit.exe` on Windows).

## Feature Flags

| Feature | Adds | Notes |
|---|---|---|
| *(default)* | Local scanning, all 29 scanners | No extra dependencies |
| `remote` | SMB2 executor, AD discovery via LDAP | Adds `ldap3` crate |
| `kerberos` | Kerberos auth (includes `remote`) | Adds `libgssapi`; macOS/Linux only |
| `winrm_compat` | Legacy WinRM client | Not used by default |

## Cross-Compiling the Windows Agent

To scan remote Windows machines from a macOS or Linux orchestrator, build a Windows executable:

```bash
# macOS — requires mingw-w64
brew install mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# Output: target/x86_64-pc-windows-gnu/release/aiaudit.exe

# From Windows
cargo build --release --features remote
```

> **Important:** Build the Windows agent **without** `--features kerberos`. GSSAPI is not available on Windows. Kerberos auth is only needed on the orchestrator side (macOS/Linux) where the binary connects to the remote host.

---

<br>

# Watch / Monitor Mode

AIAudit can run continuously and alert you the moment a new credential appears, a file's permissions change, or a local AI server starts listening on `0.0.0.0`. Perfect for individual developers — leave it running in a terminal tab or background tmux pane.

```bash
aiaudit --watch                      # 30s polling, terminal alerts
aiaudit --watch --interval 15        # faster polling
aiaudit --watch --tools claude-code powershell   # scope to specific scanners
```

### Event types

| Event | When it fires |
|-------|---------------|
| `BASELINE` | Credential existed at startup (first scan only) |
| `NEW` | Credential appeared since last scan |
| `REMOVED` | Credential gone since last scan |
| `PERMISSION_CHANGED` | File permissions changed (e.g., `0600` → `0644`) |
| `CONTENT_CHANGED` | File mtime or value preview changed |
| `RISK_ESCALATED` | Risk level went up (e.g., `MEDIUM` → `CRITICAL`) |
| `NETWORK_EXPOSED` | Local AI server started listening on `0.0.0.0` |

### Example output

```
Watch mode: interval=30s, scanners=29. Press Ctrl+C to stop.

[10:42:17] BASELINE  CRITICAL  Claude Code CLI      oauth_access_token       ~/.claude/.credentials.json
[10:42:17] BASELINE  HIGH      Docker               credsStore               ~/.docker/config.json
[10:45:03] NEW       CRITICAL  Aider                openai-api-key           ~/.aider.conf.yml
[10:47:11] PERM+     CRITICAL  Claude Code CLI      oauth_access_token       ~/.claude/.credentials.json
            └─ Permissions: 0600 → 0644
[10:51:22] NETWORK   CRITICAL  Ollama               network_exposure        0.0.0.0:11434

Watch stopped. 5 event(s) emitted.
```

---

<br>

# Remote Scanning (Windows Fleet)

Scans remote Windows machines via **SMB port 445** — no WinRM, no PowerShell remoting, no agents to install. Requires local admin credentials and access to `ADMIN$`.

### How it works

1. Connects via SMB2 and authenticates (NTLMv2 or Kerberos)
2. Uploads the Windows binary to `ADMIN$\Temp\aiaudit.exe`
3. Creates a transient SCM service, runs it, polls until done
4. Reads `ADMIN$\Temp\aiaudit_out.txt` and parses the JSON results
5. Deletes both files — leaves no trace

### Scan a Single Host

```bash
# NTLM authentication
aiaudit --remote dc01.corp.com --user CORP\svc_audit --password s3cr3t

# Kerberos — no kinit needed (requires --features kerberos build)
aiaudit --remote dc01.corp.com --kerberos --user CORP\analyst --password s3cr3t

# Kerberos with existing ticket cache
kinit analyst@CORP.COM
aiaudit --remote dc01.corp.com --kerberos

# Cross-platform: specify the Windows exe explicitly
aiaudit --remote dc01.corp.com \
  --user CORP\svc_audit --password s3cr3t \
  --remote-binary ./target/x86_64-pc-windows-gnu/release/aiaudit.exe
```

### Scan Multiple Hosts

```bash
# Inline list
aiaudit --remote dc01.corp.com ws01.corp.com ws02.corp.com \
  --user CORP\svc_audit --password s3cr3t --parallel 10

# Inventory file (JSON / YAML / CSV / plain text, one host per line)
aiaudit --inventory hosts.txt --user CORP\svc_audit --password s3cr3t

# Active Directory auto-discovery
aiaudit --ad-server ad.corp.com --ad-base-dn "DC=corp,DC=com" \
  --user CORP\svc_audit --password s3cr3t

# Write results to file while scanning
aiaudit --inventory hosts.txt --user CORP\svc_audit --password s3cr3t \
  --json-file fleet_results.json
```

### Remote Flags Reference

| Flag | Default | Description |
|---|---|---|
| `--remote HOST...` | — | One or more hostnames / IPs |
| `--inventory FILE` | — | Load hosts from JSON/YAML/CSV/text file |
| `--ad-server FQDN` | — | Discover hosts from Active Directory |
| `--ad-base-dn DN` | — | Base DN for AD host search (required with `--ad-server`) |
| `--user USER` | — | `DOMAIN\user` or `user@domain` |
| `--password PASS` | — | Password for NTLM or Kerberos AS-REQ |
| `--kerberos` | off | Use Kerberos instead of NTLM (build with `--features kerberos`) |
| `--port PORT` | 445 | SMB port |
| `--remote-binary PATH` | current exe | Path to Windows `.exe` to upload |
| `--parallel N` | 8 | Max concurrent hosts |
| `--remote-timeout SEC` | 120 | Per-host timeout |

### Inventory File Formats

**Plain text** (`hosts.txt`) — one host per line, comments with `#`:
```
dc01.corp.com
ws01.corp.com   # finance workstation
192.168.1.50
```

**JSON:**
```json
[
  { "hostname": "dc01.corp.com" },
  { "hostname": "ws01.corp.com", "tags": ["finance"] }
]
```

**YAML:**
```yaml
- hostname: dc01.corp.com
- hostname: ws01.corp.com
```

---

<br>

# CLI Reference

```bash
aiaudit [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--version` | Show version and exit |
| `--show-secrets` | Display actual credential values (requires interactive "YES" confirmation) |
| `--json` | Output JSON to stdout |
| `--json-file PATH` | Write JSON report to file |
| `--html-file PATH` | Write HTML report to file |
| `--tools SLUG...` | Only scan the specified tools (by slug) |
| `--list-tools` | List all available scanners and exit |
| `-v`, `--verbose` | Show permissions, owners, last modified, expiry, and remediation |
| `--no-color` | Disable ANSI color codes |
| `--watch` | Run continuously, alert on new/changed/removed credentials |
| `--interval SECONDS` | Watch polling interval (default: 30) |
| `--remote HOST...` | Scan remote Windows hosts via SMB |
| `--inventory FILE` | Load remote hosts from file |
| `--ad-server FQDN` | Discover remote hosts from Active Directory |
| `--ad-base-dn DN` | Base DN for AD discovery |
| `--user USER` | Credentials for remote auth (`DOMAIN\user` or UPN) |
| `--password PASS` | Password for remote auth |
| `--kerberos` | Use Kerberos instead of NTLM for remote auth |
| `--port PORT` | SMB port for remote scanning (default: 445) |
| `--remote-binary PATH` | Windows `.exe` to upload for remote scan |
| `--parallel N` | Max concurrent remote hosts (default: 8) |
| `--remote-timeout SEC` | Per-host timeout for remote scanning (default: 120) |

---

<br>

# Output Formats

### CLI Table (default)

```
Tool             Credential Type        Storage      Location                            Risk
-------------------------------------------------------------------------------------------------
Claude Code CLI  oauth_access_token     plaintext... ~/.claude/.credentials.json          CRITICAL
                   Value: sk-ant-oat01-Z...eAAA
                   Note: File last modified: 2 hours ago
                   Perms: 0600 (owner-only) Owner: sbergs
                   Fix: Restrict file permissions: chmod 600 ~/.claude/.credentials.json

Summary: 2 findings | 1 CRITICAL | 1 HIGH
```

In verbose mode (`-v`), each finding includes:
- `Last modified:` — when the credential file was last touched, with human-readable staleness ("3 hours ago", "45 days ago")
- `Fix:` — actionable remediation guidance specific to the finding

### HTML Report (`--html-file`)

Self-contained HTML file with dark theme, color-coded risk badges, and a sortable findings table. Permissions are shown with human-readable descriptions like `0777 (world-writable, world-readable, DANGEROUS)`.

### JSON Report (`--json` or `--json-file`)

Machine-readable output with full metadata — timestamps, platform info, risk summaries, and per-finding details.

### Interactive Web Dashboard (`docs/report.html`)

The repo ships a standalone HTML dashboard that reads any `results.json` and renders it as an interactive security report — no server, no install, no data leaves your machine.

```bash
aiaudit --json-file results.json && open docs/report.html
```

Then click **Load results.json** and select your output file.

Features:
- Stat cards per risk level, four charts (risk donut, tools bar, storage pie, credential types bar)
- Filterable/sortable findings grid with expandable detail rows
- Pagination, CSV export, scan errors section

## Risk Levels

| Level | Meaning | Example |
|---|---|---|
| **CRITICAL** | Plaintext + world-readable, unauthenticated network exposure, or empty auth token | `0777` credential file; Ollama/Jupyter API on `0.0.0.0`; empty `c.NotebookApp.token = ''` |
| **HIGH** | Plaintext + user-readable only, or dangerous server config | `0600` credential file; `OLLAMA_HOST=0.0.0.0` in systemd; known API key prefix in PowerShell history |
| **MEDIUM** | OS credential store, env var, or encrypted DB | Keychain, Credential Manager, `$ANTHROPIC_API_KEY`, Firefox sessionStorage |
| **LOW** | Encrypted or not present | VS Code encrypted SQLite storage |
| **INFO** | Metadata only, no secret value | Env var reference `${GITHUB_TOKEN}`, `credsStore` pointing to a credential helper |

---

<br>

# Project Structure

```
src/
├── main.rs              # Entry point
├── cli.rs               # Clap argument parsing, subcommand dispatch
├── scanner/
│   mod.rs               # CredentialFinding, ScanResult, CredentialType, RiskLevel
├── core/
│   ├── platform.rs      # OS detection (Linux/macOS/Windows/WSL), path resolution
│   ├── redactor.rs      # Secret masking with known prefix detection
│   └── permissions.rs   # File permission analysis + human-readable descriptions
├── scanners/            # One file per tool
│   ├── claude_code.rs
│   ├── claude_desktop.rs
│   ├── claude_sessions.rs
│   ├── cursor.rs
│   ├── cline.rs
│   ├── continue_dev.rs
│   ├── aider.rs
│   ├── chatgpt.rs
│   ├── gemini.rs
│   ├── huggingface.rs
│   ├── amazon_q.rs
│   ├── github_copilot.rs
│   ├── ollama.rs
│   ├── lm_studio.rs
│   ├── ml_platforms.rs
│   ├── jupyter.rs
│   ├── network_exposure.rs
│   ├── git_credentials.rs
│   ├── docker.rs
│   ├── envvars.rs
│   ├── browser_sessions.rs
│   └── ...
├── output/
│   ├── table.rs         # CLI table with ANSI colors
│   ├── json_export.rs   # JSON report
│   └── html_report.rs   # Self-contained HTML report
└── remote/              # Remote scanning (--features remote)
    ├── mod.rs           # RemoteConfig, AuthMethod
    ├── executor.rs      # PSExec-style SMB2 + SCM parallel executor
    ├── inventory.rs     # Host inventory parsing (JSON/YAML/CSV/text)
    ├── discovery.rs     # Active Directory host discovery via LDAP
    ├── scm.rs           # Windows SCM via DCE/RPC over named pipes
    └── smb/
        ├── mod.rs       # SmbSession: negotiate, auth, file I/O
        ├── auth.rs      # NTLMv2 + SPNEGO (+ Kerberos/GSSAPI under kerberos feature)
        └── proto.rs     # SMB2 packet construction and parsing
docs/
├── report.html          # Standalone web dashboard (reads results.json)
└── sample_results.json  # Sample data for testing the dashboard
```

---

<br>

# Security & Ethics

This tool is for **authorized security research, penetration testing, and defensive security assessments only**. Use it on systems you own or have explicit authorization to test.

- Credentials are **redacted by default** — `--show-secrets` requires explicit `YES` confirmation
- The tool is **read-only** — it never modifies, exfiltrates, or transmits any credentials
- JSON output **never includes raw values** even with `--show-secrets`

---

## License

MIT
