---
name: cyberlens
description: Scan websites and GitHub repositories for practical security issues using CyberLens cloud analysis and local web fallback checks.
metadata: {"openclaw": {"requires": {"bins": ["python3"]}, "primaryEnv": "CYBERLENS_API_KEY", "emoji": "\ud83d\udd12", "homepage": "https://cyberlensai.com"}}
---

# CyberLens Security Scanner

Scan websites and GitHub repositories for practical security issues before you ship, install, or trust them. CyberLens can audit live web targets for missing headers, HTTPS weaknesses, exposed technologies, and insecure forms, and it can also scan repositories and OpenClaw skills hosted on GitHub through the CyberLens cloud service. Results include a 0-100 security score, letter grade (A-F), and plain-English remediation advice.

## Prerequisites

- **Python 3.9+**: Required for script execution
- **Python Packages**:
  ```bash
  pip install -r requirements.txt
  ```

## First-Time Setup

Before scanning, the user must connect their CyberLens account. Run the `connect_account` tool. This opens a browser to cyberlensai.com where they sign in or create an account. A short-lived connect code is delivered through the callback, the skill exchanges that code for the real account key over HTTPS on official CyberLens hosts, and the key is stored at `~/.openclaw/skills/cyberlens/config.yaml`.

Browser authentication uses `https://cyberlensai.com/connect`. The hosted scan API runs at `https://api.cyberlensai.com/functions/v1/public-api-scan`. If the user needs to override the scan API endpoint explicitly, set `CYBERLENS_API_BASE_URL`.

If the user doesn't have a CyberLens account, direct them to https://cyberlensai.com to sign up. Free tier includes 5 scans/month (2 website + 3 repository). Repository scanning requires a connected account.

## Tools

### connect_account

Connect or reconnect a CyberLens account. Opens the browser to cyberlensai.com/connect, waits for authentication, validates the returned exchange host against official CyberLens infrastructure, and stores the API key locally.

```bash
python3 -c "
import asyncio
from cyberlens_skill.src.tools import connect_account
result = asyncio.run(connect_account())
print(result)
"
```

Use this when:
- The user wants to connect their CyberLens account
- The user gets an authentication error during scanning
- The user wants to switch to a different account

If OpenClaw is running on another machine, set `CYBERLENS_CONNECT_CALLBACK_URL` to a browser-reachable callback URL before running `connect_account`. Use `CYBERLENS_CONNECT_BIND_HOST` and `CYBERLENS_CONNECT_BIND_PORT` when a reverse proxy or different local bind address is involved. If no callback path is available, the user can still set `CYBERLENS_API_KEY` manually. If the user prefers not to persist the key on disk, they can keep `CYBERLENS_API_KEY` only in the process environment.

### scan_target

Scan either a live website or a GitHub repository URL. CyberLens auto-detects the target type. Website scans can use the local fallback engine. Repository scans require the CyberLens cloud API.

Parameters:
- `target` (required): Website URL or GitHub repository URL
- `scan_depth`: "quick", "standard" (default), or "deep"
- `timeout`: Request timeout in seconds (default: 30)
- `use_cloud`: Force cloud (true) or local (false) scanning. Repository scans require cloud.

```bash
python3 -c "
import asyncio
from cyberlens_skill.src.tools import scan_target
result = asyncio.run(scan_target('https://github.com/shadoprizm/cyberlens-skill'))
print(result)
"
```

### scan_website

Scan a website URL for security vulnerabilities. Uses the CyberLens cloud API when connected (70+ checks), falls back to local scanning if not. For repository URLs, use `scan_target` or `scan_repository`.

Parameters:
- `url` (required): The website URL to scan (must include https:// or http://)
- `scan_depth`: "quick", "standard" (default), or "deep"
- `timeout`: Request timeout in seconds (default: 30)
- `use_cloud`: Force cloud (true) or local (false) scanning. Auto-detects by default.

```bash
python3 -c "
import asyncio
from cyberlens_skill.src.tools import scan_website
result = asyncio.run(scan_website('https://example.com'))
print(result)
"
```

Returns: score (0-100), grade (A-F), findings with severity/description/remediation, and scan source (cloud or local).

### scan_repository

Scan a GitHub repository URL, including OpenClaw skills before installation. Repository scans use the CyberLens cloud API and return repository findings, dependency alerts, trust posture findings, and security/trust scores.

Parameters:
- `repository_url` (required): GitHub repository URL such as `https://github.com/owner/repo`
- `timeout`: Request timeout in seconds (default: 60)
- `use_cloud`: Force cloud behavior. Repository scans require cloud access.

```bash
python3 -c "
import asyncio
from cyberlens_skill.src.tools import scan_repository
result = asyncio.run(scan_repository('https://github.com/shadoprizm/cyberlens-skill'))
print(result)
"
```

### get_security_score

Quick security score check. Faster than a full scan when you only need the grade. For GitHub repositories, this returns the repository security score from the CyberLens cloud report.

Parameters:
- `url` (required): The website URL to check
- `timeout`: Request timeout in seconds (default: 30)

```bash
python3 -c "
import asyncio
from cyberlens_skill.src.tools import get_security_score
result = asyncio.run(get_security_score('https://example.com'))
print(result)
"
```

### explain_finding

Get a plain-English explanation of a security finding type.

Parameters:
- `finding_type` (required): e.g., "missing-csp", "no-https", "missing-hsts"
- `context` (optional): Where the finding was detected

Known finding types: missing-csp, missing-hsts, missing-x-frame-options, missing-x-content-type-options, missing-referrer-policy, missing-permissions-policy, no-https, information-disclosure, server-version-exposed, insecure-form-action, missing-csrf-protection

### list_scan_rules

List all available scan rules organized by category (headers, https, disclosure, forms).

## Account Tiers

| Tier | Scans/Month |
|------|-------------|
| Free | 5 (2 website + 3 repo) |
| Starter | 10 |
| Advanced | 40 |
| Premium | 100 |
| Agency | Custom |

## Notes

- Cloud scanning is more thorough than local (70+ checks vs ~15 local checks)
- Repository and OpenClaw skill scanning require a connected CyberLens account
- If the API key is invalid or expired, suggest running `connect_account` again
- Scan results from the cloud match exactly what cyberlensai.com shows
- Local fallback scanning works for website targets without an account but has fewer checks
