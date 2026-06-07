# AIAudit

**AI Credential & Secrets Scanner**

AIAudit is a fast, read-only Rust binary that finds exposed API keys, OAuth tokens, MCP server secrets, and session credentials across 29 AI tools on Windows, macOS, Linux, and WSL. Run it locally in seconds, or push it to remote Windows machines via SMB and scan an entire fleet without installing anything.

> Credentials are **redacted by default** — output is safe to include in reports and screenshots. Use `--show-secrets` only on your own machine when you need the raw values.

---

## Quick Start

```bash
git clone https://github.com/netwrix/AIHound.git
cd AIHound
cargo build --release
./target/release/aiaudit
```

**Sample output:**

```
Tool             Credential Type        Storage       Location                             Risk
----------------------------------------------------------------------------------------------
Claude Code CLI  oauth_access_token     plaintext_… ~/.claude/credentials.json            CRITICAL
                   Value: sk-ant-oat01-Z...eAAA
Claude Desktop   mcp_env:GITHUB_TOKEN   plaintext_… ~/Library/…/claude_desktop_config.json HIGH
Cursor IDE       api_key                plaintext_… ~/Library/…/state.vscdb               HIGH
GitHub Copilot   oauth_access_token     plaintext_… ~/.config/github-copilot/hosts.json   HIGH

Summary: 4 findings | 1 CRITICAL | 3 HIGH
```

---

## What Gets Scanned

### AI Coding Assistants & Agents

| Slug | Tool | What It Finds |
|---|---|---|
| `claude-code` | Claude Code CLI | OAuth access/refresh tokens, MCP env secrets, backup credentials |
| `claude-desktop` | Claude Desktop | MCP server env vars and inline headers from `claude_desktop_config.json` |
| `claude-sessions` | Claude Sessions | Saved session count and storage location |
| `cursor` | Cursor IDE | API keys in VS Code SQLite state DB |
| `cline` | Cline (VS Code) | API keys in `cline_mcp_settings.json` |
| `continue-dev` | Continue.dev | API keys in `config.json` |
| `aider` | Aider | API keys in `~/.aider.conf.yml` |
| `windsurf` | Windsurf | API keys and auth tokens |
| `openclaw` | OpenClaw | Auth tokens |
| `vscode-extensions` | VS Code Extensions | Keys stored by AI extensions |

### AI Services & APIs

| Slug | Tool | What It Finds |
|---|---|---|
| `chatgpt` | ChatGPT Desktop | OAuth session tokens |
| `gemini` | Gemini CLI / GCloud | API keys, service account refs in `~/.config/gemini/` and ADC |
| `openai-cli` | OpenAI/Codex CLI | API keys in `~/.openai/` |
| `huggingface` | Hugging Face CLI | Access tokens in `~/.cache/huggingface/token` |
| `amazon-q` | Amazon Q / AWS | SSO cache tokens in `~/.aws/sso/cache/` |

### Local AI Infrastructure

| Slug | Tool | What It Finds |
|---|---|---|
| `ollama` | Ollama | Auth tokens, API keys if configured |
| `lm-studio` | LM Studio | Keys and auth config |
| `ml-platforms` | Replicate / Together / Groq | API keys in `~/.config/` |
| `jupyter` | Jupyter | Server tokens in `jupyter_server_config.json` and running config |
| `network-exposure` | AI Network Exposure | Unauthenticated AI services listening on localhost (Ollama :11434, LM Studio :1234, Jupyter :8888, Gradio :7860, vLLM :8000, LocalAI :8080, Open WebUI :3000, ComfyUI :8188) |

### Developer Infrastructure

| Slug | Tool | What It Finds |
|---|---|---|
| `github-copilot` | GitHub Copilot | OAuth tokens in `hosts.json`, session tokens |
| `git-credentials` | Git Credentials | Plaintext passwords in `~/.git-credentials` and `~/.gitconfig` |
| `docker` | Docker | Registry auth in `~/.docker/config.json` |
| `envvars` | Environment Variables | AI API keys set in the current environment |
| `persistent-env` | Persistent Environment | Keys exported in shell profiles that survive reboots |
| `shell-rc` | Shell RC Files | API keys hardcoded in `.bashrc`, `.zshrc`, etc. |
| `shell-history` | Shell History | API keys leaked via CLI invocations in `.zsh_history`, `.bash_history` |
| `powershell` | PowerShell Logs | Keys leaked in PowerShell transcript/history logs (Windows) |
| `browser-sessions` | Browser Sessions | AI service cookies / session storage |

---

## Data Points Collected Per Finding

Every finding captures:

| Field | Description |
|---|---|
| **Tool** | Name of the AI tool |
| **Credential Type** | What the secret is (`api_key`, `oauth_access_token`, `mcp_env:VAR_NAME`, `env_var:NAME`, `git_credential`, etc.) |
| **Storage Type** | How it's stored (`plaintext_json`, `plaintext_yaml`, `plaintext_env`, `plaintext_file`, `plaintext_ini`, `keychain`, `credential_manager`, `encrypted_db`, `environment_var`) |
| **Location** | File path or environment variable name |
| **Risk Level** | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| **Value Preview** | Redacted snippet showing prefix and last 4 chars (e.g. `sk-ant-...eAAA`) |
| **File Permissions** | Unix mode string (`0644`) or Windows ACL summary |
| **File Owner** | Username that owns the file |
| **Last Modified** | Timestamp and human-readable staleness (`"32 days ago"`) |
| **Expiry** | Token expiry if present in the file |
| **Notes** | Context-specific observations (e.g. `"Token age: 56 days"`, `"File is world-readable"`) |
| **Remediation** | Specific fix steps for this finding |

---

## Risk Levels

| Level | Meaning | Typical Action |
|---|---|---|
| **CRITICAL** | Secret in a world-readable file, or hardcoded in a notebook/history | Fix file permissions (`chmod 600`) and rotate the key |
| **HIGH** | Plaintext secret readable only by its owner | Acceptable short-term; move to OS keychain when possible |
| **MEDIUM** | OS credential store or environment variable | Standard practice; review scope and expiry |
| **LOW** | Encrypted storage or local-only service | Generally acceptable |
| **INFO** | Metadata or configuration flag — not a secret | No action needed |

---

## Usage

### Local Scan (default)

```bash
# Basic scan — all applicable tools
aiaudit

# Verbose — shows permissions, owner, last modified, expiry, remediation
aiaudit -v

# Scan only specific tools
aiaudit --tools claude-code claude-desktop envvars

# List all available scanners
aiaudit --list-tools

# Show raw credential values (requires a TTY, asks for confirmation)
aiaudit --show-secrets
```

### Output Formats

```bash
# JSON to stdout (pipe-friendly)
aiaudit --json

# JSON to file
aiaudit --json-file results.json

# HTML report
aiaudit --html-file report.html

# All at once
aiaudit -v --json-file results.json --html-file report.html
```

### Watch Mode — Continuous Monitoring

Alerts on new, changed, or escalated credentials in real time. Useful for CI/CD pipelines or leaving running during a pentest.

```bash
# Re-scan every 30 seconds (default)
aiaudit --watch

# Custom interval
aiaudit --watch --interval 60
```

---

## Interactive Web Report

The repo ships a standalone HTML dashboard (`docs/report.html`) that reads any `results.json` and renders it as an interactive security report — no server, no install, no data leaves your machine.

**Open it in your browser:**

```bash
open docs/report.html
# or: xdg-open docs/report.html   (Linux)
# or: start docs\report.html      (Windows)
```

Then click **Load results.json** and select your output file.

**Features:**
- Stat cards — total findings with a card per risk level
- Four charts — findings by risk (donut), top AI tools (bar), storage type (pie), credential types (bar)
- Filterable, sortable findings grid — filter by risk, tool, storage type, or free-text search
- Expandable detail rows — permissions, owner, last modified, expiry, full path, remediation
- Pagination (25 rows/page)
- CSV export of the current filtered view
- Scan errors listed separately

**Generate and view in one step:**

```bash
aiaudit --json-file results.json && open docs/report.html
```

---

## Remote Scanning (Windows Fleet)

Scans remote Windows machines via **SMB port 445** — no WinRM, no PowerShell remoting, no agents to install. Requires local admin credentials and access to `ADMIN$`.

How it works:
1. Connects via SMB2 and authenticates (NTLMv2 or Kerberos)
2. Uploads the Windows binary to `ADMIN$\Temp\aiaudit.exe`
3. Creates a transient SCM service, runs it, polls until done
4. Reads `ADMIN$\Temp\aiaudit_out.txt` and parses the JSON results
5. Deletes both files — leaves no trace

### Build the Windows Binary

```bash
# From macOS/Linux — requires mingw-w64
brew install mingw-w64  # macOS
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# Binary: target/x86_64-pc-windows-gnu/release/aiaudit.exe

# On Windows, just:
cargo build --release --features remote
```

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

## Building

```bash
# Default (local scan only)
cargo build --release

# With remote scanning (SMB + AD discovery)
cargo build --release --features remote

# With remote + Kerberos auth (macOS/Linux only; not needed for the Windows agent)
cargo build --release --features kerberos

# Cross-compile Windows agent from macOS
brew install mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# Note: build WITHOUT --features kerberos for the Windows agent
```

### Feature Flags

| Feature | Adds | Notes |
|---|---|---|
| *(default)* | Local scanning, all 29 scanners | No extra dependencies |
| `remote` | SMB2 executor, AD discovery via LDAP | Adds `ldap3` crate |
| `kerberos` | Kerberos auth (includes `remote`) | Adds `libgssapi`; macOS/Linux only |
| `winrm_compat` | Legacy WinRM client | Adds `reqwest`; not used by default |

---

## WSL

On WSL, AIAudit automatically detects the environment and scans **both**:
- Linux-native paths (`~/.claude/`, `~/.aws/`, etc.)
- Windows paths via `/mnt/c/Users/<username>/AppData/...`

This often surfaces credentials in Windows app data with overly permissive permissions (`0777`) that only become visible from the WSL side.

---

## Common Findings

### `oauth_access_token` / `oauth_refresh_token` — Claude Code
Stored in `~/.claude/credentials.json`. The access token is short-lived (hours); the **refresh token is long-lived** and can mint new access tokens indefinitely. Treat it the same as a password.

### `mcp_env:TOKEN_NAME` — Claude Desktop / MCP Servers
MCP server configurations in `claude_desktop_config.json` often embed secrets directly. Replace hardcoded values with environment variable references in your shell profile and reference them as `"env:VAR_NAME"` in the config.

### `api_key` — Continue.dev / Cline
Both tools store API keys in plaintext config files. Use the `${ENV_VAR}` syntax supported by each tool to avoid writing the key to disk.

### `network_exposure` — Jupyter / Ollama / Gradio
Unauthenticated AI services listening on localhost can be accessed by any local user or process. Bind to `127.0.0.1` explicitly and enable authentication where supported.

### `git_credential` — Git Credentials
`~/.git-credentials` stores plaintext passwords. Migrate to the OS credential helper:
```bash
git config --global credential.helper osxkeychain   # macOS
git config --global credential.helper manager        # Windows
```
