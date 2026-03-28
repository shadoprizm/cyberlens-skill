# CyberLens OpenClaw Skill

> Scan Claw Hub skills, websites, and GitHub repositories for security issues — directly from OpenClaw

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

An [OpenClaw](https://openclaw.com) skill that lets AI agents scan [Claw Hub](https://clawhub.ai) skills, live websites, and GitHub repositories for practical security issues before you install or trust them. Paste a Claw Hub link, and CyberLens analyses the skill package for vulnerabilities, malicious code, dependency risks, secret leaks, and trust posture problems — powered by the [CyberLens](https://cyberlensai.com) cloud analysis engine. Results include a security score, trust score, AI-powered analysis, and plain-English remediation advice. Get your report rendered in chat or exported as a downloadable PDF.

**Free tier includes 5 scans/month** (2 website + 3 repository/skill) — no credit card required. [Sign up at cyberlensai.com](https://cyberlensai.com)

## Why Install CyberLens

- **Scan Claw Hub skills before you install them.** Paste a `clawhub.ai` link and get a full security assessment.
- Scan live websites and GitHub repositories from the same skill.
- Catch missing headers, HTTPS problems, insecure forms, dependency risks, malicious code, and trust posture issues.
- **Get reports in chat or as a PDF** — choose markdown for messaging (Telegram, Discord, Signal) or export a PDF to download, email, or archive.
- AI-powered analysis explains what the findings mean and what to do about them.
- Use deeper cloud scans when connected, with a local website fallback when you are not.
- **Free scans available** — get started with 5 free scans/month, no account setup required for local website checks.

## Installation

### Via OpenClaw Skills Directory

Copy or symlink into your OpenClaw skills folder:

```bash
# Symlink (recommended for development)
ln -s /path/to/cyberlens-skill ~/.openclaw/skills/cyberlens

# Or copy
cp -r /path/to/cyberlens-skill ~/.openclaw/skills/cyberlens
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

For a reproducible install of the skill's pinned direct dependencies, use:

```bash
pip install -r requirements.lock
```

OpenClaw auto-discovers the skill from the `SKILL.md` file on the next session (or ask your agent to "refresh skills").

### Configuration in openclaw.json (Optional)

```json
{
  "skills": {
    "entries": {
      "cyberlens": {
        "enabled": true
      }
    }
  }
}
```

## Connecting Your Account

The first time you use the skill, tell your agent to "connect my CyberLens account" (or it will prompt you). This runs the `connect_account` tool, which:

1. Opens your browser to [cyberlensai.com/connect](https://cyberlensai.com/connect)
2. You sign in or create a free account
3. A callback server receives a short-lived connect code
4. The skill exchanges that code for your account key over HTTPS
5. The key is stored at `~/.openclaw/skills/cyberlens/config.yaml`

No copy-pasting required. The raw account key no longer appears in the browser callback URL. The skill only accepts HTTPS exchange URLs on official CyberLens hosts, then detects the key on subsequent scans and routes through the cloud API automatically.

You can also set the key via environment variable: `CYBERLENS_API_KEY`.
The browser-based connect flow uses `https://cyberlensai.com/connect`, while the hosted scan API runs at `https://api.cyberlensai.com/functions/v1/public-api-scan`. If you need to override that endpoint explicitly, set `CYBERLENS_API_BASE_URL`.

### Remote or Server Installs

If OpenClaw is running on a different machine than the browser you use to sign in, set a browser-reachable callback URL before running `connect_account`.

Examples:

```bash
# Direct LAN or VPN callback
export CYBERLENS_CONNECT_CALLBACK_URL="http://10.0.0.5:54321/callback"

# Hosted HTTPS callback behind a reverse proxy
export CYBERLENS_CONNECT_CALLBACK_URL="https://openclaw.example.com/cyberlens/callback"
export CYBERLENS_CONNECT_BIND_HOST="127.0.0.1"
export CYBERLENS_CONNECT_BIND_PORT="54321"
```

`CYBERLENS_CONNECT_BIND_HOST` and `CYBERLENS_CONNECT_BIND_PORT` are optional. Use them when the skill should listen on a different local interface or port than the public callback endpoint. For hosted HTTPS callbacks, your proxy must forward requests to the bind host and port where the skill is listening.

If you do not want to expose a callback at all, set `CYBERLENS_API_KEY` manually instead. If you do not want the key stored on disk, keep it only in the process environment. When the key is stored locally, the skill writes it with restrictive file permissions where the OS supports them.

## Tools

### scan_skill

Scan a Claw Hub skill before installing it. This is the primary tool for vetting OpenClaw skills from the Claw Hub marketplace.

**Parameters:**
- `skill_url` (required) -- Claw Hub skill URL (e.g. `https://clawhub.ai/author/skill-name`) or GitHub repository URL for an OpenClaw skill
- `timeout` -- Request timeout in seconds (default: 60)

**Example prompts:**
- "Scan https://clawhub.ai/anthropic/tavily-search before I install it"
- "Is this Claw Hub skill safe? https://clawhub.ai/author/skill-name"
- "Check this skill for malicious code before I install it"

**Returns:** Security score, trust score, grade (A-F), AI analysis, and detailed findings by category (security, dependencies, trust posture, secrets, malicious code, behavioural, artifacts).

### scan_target

Scan a live website, GitHub repository, or Claw Hub skill URL. CyberLens auto-detects the target type.

**Parameters:**
- `target` (required) -- Website URL, GitHub repository URL, or Claw Hub skill URL
- `scan_depth` -- `"quick"`, `"standard"` (default), or `"deep"`
- `timeout` -- Request timeout in seconds (default: 30)
- `use_cloud` -- Force cloud (`true`) or local (`false`). Repository and skill scans require cloud.

**Example prompts:**
- "Scan https://clawhub.ai/author/skill-name for security issues"
- "Scan https://example.com for security issues"
- "Scan https://github.com/shadoprizm/cyberlens-skill before I install it"

### connect_account

Connect or reconnect your CyberLens account for cloud-powered scanning.

**Example prompt:** "Connect my CyberLens account"

### scan_website

Scan a website for security vulnerabilities. Uses the cloud API when connected, local engine otherwise.

**Parameters:**
- `url` (required) -- The URL to scan (must include `https://` or `http://`)
- `scan_depth` -- `"quick"`, `"standard"` (default), or `"deep"`
- `timeout` -- Request timeout in seconds (default: 30)
- `use_cloud` -- Force cloud (`true`) or local (`false`). Auto-detects by default.

**Example prompts:**
- "Scan https://example.com for security issues"
- "Do a deep security scan of https://mysite.com"
- "Check if https://example.com is secure"

**Returns:** Score (0-100), grade (A-F), findings with severity/description/remediation, and scan source (cloud or local).

### scan_repository

Scan a GitHub repository URL, including OpenClaw skills before installation.

**Parameters:**
- `repository_url` (required) -- GitHub repository URL (e.g. `https://github.com/owner/repo`) or Claw Hub skill URL
- `timeout` -- Request timeout in seconds (default: 60)
- `use_cloud` -- Force cloud (`true`) or local (`false`). Repository scans require cloud access.

**Example prompts:**
- "Scan https://github.com/shadoprizm/cyberlens-skill for repo vulnerabilities"
- "Audit this OpenClaw skill before I install it"
- "Check my GitHub repo for security issues"

**Returns:** Repository security score, trust score, aggregated findings, and the underlying repository assessment sections from CyberLens cloud analysis.

### generate_report

Generate a formatted markdown report from any scan result. Suitable for sharing in Telegram, Discord, Signal, the web UI, or any channel that renders markdown.

**Parameters:**
- `scan_result` (required) -- The result returned by any CyberLens scan tool

**Example prompts:**
- "Show me the report in chat"
- "Give me a summary of the scan results"
- "Share the findings here"

**Returns:** A clean markdown report with score cards, AI analysis, summary, and severity-sorted findings.

### export_report_pdf

Export scan results as a professionally formatted PDF file with colour-coded severity indicators and full findings detail.

**Parameters:**
- `scan_result` (required) -- The result returned by any CyberLens scan tool
- `output_path` (optional) -- Where to save the PDF. Defaults to `~/cyberlens-report-<timestamp>.pdf`

**Example prompts:**
- "Export that scan as a PDF"
- "Give me a downloadable report"
- "Save the results as a PDF file"

**Returns:** Absolute path to the generated PDF file.

### get_security_score

Quick score check -- faster when you only need the grade. Supports websites, GitHub repositories, and Claw Hub skill URLs.

**Parameters:**
- `url` (required) -- The URL to check
- `timeout` -- Request timeout in seconds (default: 30)

**Example prompt:** "What's the security grade for https://clawhub.ai/author/skill-name?"

### explain_finding

Get a plain-English explanation of a security finding.

**Parameters:**
- `finding_type` (required) -- e.g., `"missing-csp"`, `"no-https"`, `"missing-hsts"`
- `context` (optional) -- Additional context about where the finding was detected

**Known finding types:** `missing-csp`, `missing-hsts`, `missing-x-frame-options`, `missing-x-content-type-options`, `missing-referrer-policy`, `missing-permissions-policy`, `no-https`, `information-disclosure`, `server-version-exposed`, `insecure-form-action`, `missing-csrf-protection`

### list_scan_rules

List all available detection rules organized by category (headers, HTTPS, disclosure, forms, repository).

## Cloud vs Local Scanning

| | Local | Cloud |
|---|---|---|
| Checks | ~15 core rules | 70+ rules |
| Account required | No | Yes |
| Results match website | No | Yes |
| Scan history | No | Yes |
| Claw Hub skill scanning | No | Yes |
| Repository scanning | No | Yes |
| AI-powered analysis | No | Yes |
| PDF report export | Yes (from any result) | Yes (from any result) |

When connected, cloud scanning is used by default. If a website cloud scan fails (network issues, quota exceeded), the skill automatically falls back to local scanning unless `use_cloud=True` was explicitly set. Claw Hub skill scanning and repository scanning use the cloud service and do not have a local fallback.

## Account Tiers

| Tier | Scans/Month | Price |
|------|-------------|-------|
| **Free** | **5 (2 website + 3 repo/skill)** | **Free** |
| Starter | 10 | Paid |
| Advanced | 40 | Paid |
| Premium | 100 | Paid |
| Agency | Custom | Custom |

**Get started free** — 5 scans/month with no credit card required. Sign up at [cyberlensai.com](https://cyberlensai.com).

## Project Structure

```
cyberlens-skill/
  SKILL.md              # OpenClaw skill manifest (YAML frontmatter + instructions)
  skill.yaml            # Skill metadata and config schema
  requirements.txt      # Python dependencies
  requirements.lock     # Pinned direct dependencies for reproducible installs
  SECURITY.md           # Vulnerability reporting policy
  CONTRIBUTING.md       # Contribution workflow and expectations
  LICENSE               # Apache 2.0 license
  .github/workflows/ci.yml  # Automated test workflow
  src/
    __init__.py         # Package exports
    tools.py            # Tool implementations (connect, scan, scan_skill, report, PDF, score, explain, rules)
    scanner.py          # Local SecurityScanner (async, httpx + BeautifulSoup)
    api_client.py       # CyberLens cloud API client (async, exponential backoff)
    auth.py             # Browser-based connect flow with secure code exchange
    models.py           # Pydantic data models
  examples/
    basic_scan.py
    batch_scan.py
    custom_rules.py
  tests/
```

## Dependencies

- `httpx` -- Async HTTP client
- `beautifulsoup4` -- HTML parsing (for local scanning)
- `pydantic` -- Data validation
- `pyyaml` -- Config file handling
- `reportlab` -- PDF report generation

The local scanner uses Python's built-in `html.parser` via BeautifulSoup, so `lxml` is not required for the default install.

## Security

Please review [SECURITY.md](SECURITY.md) before reporting vulnerabilities. Sensitive reports should not be filed as public issues.

## Related Repositories

| Repository | Description |
|------------|-------------|
| [cyberlens-oss](https://github.com/shadoprizm/cyberlens-oss) | Core Python scanner and CLI |
| [cyberlens-extension](https://github.com/shadoprizm/cyberlens-extension) | Chrome extension |
| [cyberlens-examples](https://github.com/shadoprizm/cyberlens-examples) | Integration examples and tutorials |

## License

Apache 2.0 -- see [LICENSE](LICENSE).

---

Part of the [CyberLens](https://cyberlensai.com) open-source security platform.
