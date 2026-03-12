# CyberLens - OpenClaw Skill

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

> **AI-powered website security scanning for OpenClaw agents**

CyberLens is a lightweight, fast security scanner that helps AI agents check websites for common vulnerabilities and misconfigurations. Get instant security scores, detailed findings, and plain-English explanations.

## Features

- **🔒 Security Scanning** - Detect HTTPS issues, missing security headers, exposed information
- **📊 Security Scoring** - 0-100 score with letter grade (A-F) for quick assessment
- **🧠 AI-Ready Explanations** - Convert technical findings into actionable advice
- **⚡ Fast & Lightweight** - Async HTTP client, typical scan completes in under 3 seconds
- **🔧 Extensible Rules** - Add custom detection rules for specialized needs

## Tools Included

| Tool | Description |
|------|-------------|
| `scan_website` | Full security scan with detailed findings |
| `get_security_score` | Quick score check (faster than full scan) |
| `explain_finding` | Get plain-English explanation of any finding |
| `list_scan_rules` | See all available detection rules |

## Quick Start

```python
# Full security scan
result = await scan_website("https://example.com")
print(f"Security Score: {result.score}/100 (Grade: {result.grade})")

# Quick score check
score = await get_security_score("https://example.com")
print(f"Grade: {score.grade}")  # A, B, C, D, or F

# Understand a finding
explanation = await explain_finding("missing-csp")
print(explanation.remediation)
```

## What Gets Scanned

- **HTTPS Configuration** - Certificate validity, TLS version, cipher suites
- **Security Headers** - CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
- **Information Disclosure** - Server banners, X-Powered-By, exposed paths
- **Technology Detection** - Framework and server fingerprinting
- **Form Security** - Insecure form actions, missing CSRF tokens

## Example Output

```json
{
  "score": 72,
  "grade": "C",
  "findings": [
    {
      "type": "missing-csp",
      "severity": "medium",
      "description": "Content-Security-Policy header is missing",
      "remediation": "Add CSP header to prevent XSS attacks"
    },
    {
      "type": "missing-hsts",
      "severity": "high",
      "description": "HTTP Strict Transport Security not enabled",
      "remediation": "Add Strict-Transport-Security header"
    }
  ]
}
```

## Installation

This skill is designed to be used within the OpenClaw ecosystem. Install via:

```bash
openclaw skills install cyberlens
```

Or clone and install locally:

```bash
git clone https://github.com/shadoprizm/cyberlens-skill.git
cd cyberlens-skill
pip install -r requirements.txt
```

## Configuration

Optional configuration in your OpenClaw config:

```yaml
skills:
  cyberlens:
    timeout_seconds: 30
    max_redirects: 5
    user_agent: "MyAgent/1.0"
```

## Use Cases

- **Pre-deployment checks** - Scan before shipping to production
- **Security monitoring** - Regular scans of critical sites
- **Competitive analysis** - Compare security posture of competitors
- **Client reporting** - Generate security reports for stakeholders
- **CI/CD integration** - Fail builds on security regressions

## Contributing

Contributions welcome! See the main [CyberLens repository](https://github.com/shadoprizm/cyberlens) for guidelines.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

**Part of the CyberLens open-source security platform**  
🔗 https://github.com/shadoprizm/cyberlens
