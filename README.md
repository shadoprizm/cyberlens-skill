# CyberLens OpenClaw Skill

> Website security scanning for OpenClaw AI agents

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

An [OpenClaw](https://openclaw.com) skill that gives AI agents the ability to scan websites for security vulnerabilities. When connected to a [CyberLens](https://cyberlensai.com) account, scans run through the cloud API with 70+ checks and results match the web dashboard. Falls back to local scanning (~15 checks) without an account.

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

No copy-pasting required. The raw account key no longer appears in the browser callback URL. The skill detects the key on subsequent scans and routes through the cloud API automatically.

You can also set the key via environment variable: `CYBERLENS_API_KEY`.

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

If you do not want to expose a callback at all, set `CYBERLENS_API_KEY` manually instead.

## Tools

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

### get_security_score

Quick score check -- faster when you only need the grade.

**Parameters:**
- `url` (required) -- The URL to check
- `timeout` -- Request timeout in seconds (default: 30)

**Example prompt:** "What's the security grade for https://example.com?"

### explain_finding

Get a plain-English explanation of a security finding.

**Parameters:**
- `finding_type` (required) -- e.g., `"missing-csp"`, `"no-https"`, `"missing-hsts"`
- `context` (optional) -- Additional context about where the finding was detected

**Known finding types:** `missing-csp`, `missing-hsts`, `missing-x-frame-options`, `missing-x-content-type-options`, `missing-referrer-policy`, `missing-permissions-policy`, `no-https`, `information-disclosure`, `server-version-exposed`, `insecure-form-action`, `missing-csrf-protection`

### list_scan_rules

List all available detection rules organized by category (headers, HTTPS, disclosure, forms).

## Cloud vs Local Scanning

| | Local | Cloud |
|---|---|---|
| Checks | ~15 core rules | 70+ rules |
| Account required | No | Yes |
| Results match website | No | Yes |
| Scan history | No | Yes |
| Repository scanning | No | Yes |

When connected, cloud scanning is used by default. If the cloud scan fails (network issues, quota exceeded), the skill automatically falls back to local scanning unless `use_cloud=True` was explicitly set.

## Account Tiers

| Tier | Scans/Month |
|------|-------------|
| Free | 5 (2 website + 3 repository) |
| Starter | 10 |
| Advanced | 40 |
| Premium | 100 |
| Agency | Custom |

Sign up at [cyberlensai.com](https://cyberlensai.com).

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
    tools.py            # Tool implementations (connect, scan, score, explain, rules)
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
