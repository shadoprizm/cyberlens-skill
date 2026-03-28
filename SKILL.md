---
name: cyberlens
description: Scan websites for security vulnerabilities using the CyberLens cloud API. Connect your CyberLens account, scan URLs, get security scores, and explain findings in plain English.
metadata: {"openclaw": {"requires": {"bins": ["python3"]}, "primaryEnv": "CYBERLENS_API_KEY", "emoji": "\ud83d\udd12", "homepage": "https://cyberlensai.com"}}
---

# CyberLens Security Scanner

Scan websites for security vulnerabilities using the CyberLens cloud API at cyberlensai.com. Results include a 0-100 security score, letter grade (A-F), and detailed findings with severity levels and remediation advice.

## Prerequisites

- **Python 3.9+**: Required for script execution
- **Python Packages**:
  ```bash
  pip install -r requirements.txt
  ```

## First-Time Setup

Before scanning, the user must connect their CyberLens account. Run the `connect_account` tool. This opens a browser to cyberlensai.com where they sign in or create an account. A short-lived connect code is delivered through the callback, the skill exchanges that code for the real account key over HTTPS, and the key is stored at `~/.openclaw/skills/cyberlens/config.yaml`.

If the user doesn't have a CyberLens account, direct them to https://cyberlensai.com to sign up. Free tier includes 5 scans/month (2 website + 3 repository).

## Tools

### connect_account

Connect or reconnect a CyberLens account. Opens the browser to cyberlensai.com/connect, waits for authentication, and stores the API key locally.

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

If OpenClaw is running on another machine, set `CYBERLENS_CONNECT_CALLBACK_URL` to a browser-reachable callback URL before running `connect_account`. Use `CYBERLENS_CONNECT_BIND_HOST` and `CYBERLENS_CONNECT_BIND_PORT` when a reverse proxy or different local bind address is involved. If no callback path is available, the user can still set `CYBERLENS_API_KEY` manually.

### scan_website

Scan a website URL for security vulnerabilities. Uses the CyberLens cloud API when connected (70+ checks), falls back to local scanning if not.

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

### get_security_score

Quick security score check. Faster than a full scan when only the score is needed.

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
- If the API key is invalid or expired, suggest running `connect_account` again
- Scan results from the cloud match exactly what cyberlensai.com shows
- Local fallback scanning works without an account but has fewer checks
