"""Tool function implementations for OpenClaw integration."""

from typing import List, Dict, Any, Optional
from .scanner import SecurityScanner
from .api_client import CyberLensAPIClient
from .auth import load_api_key, run_connect_flow
from .models import (
    ScanResult,
    SecurityScore,
    Finding,
    FindingExplanation,
    ScanRule,
)


# Finding explanations database
FINDING_EXPLANATIONS = {
    "missing-csp": {
        "explanation": "Content Security Policy (CSP) is a browser security feature that controls what resources (scripts, styles, images) can load on your page. Without it, attackers can inject malicious scripts that steal data or take over user sessions.",
        "severity": "medium",
        "remediation": "Add a Content-Security-Policy header to your HTTP responses. Start with a permissive policy like \"default-src 'self'\" and gradually tighten it as you test.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "https://csp-evaluator.withgoogle.com/",
        ],
    },
    "missing-hsts": {
        "explanation": "HTTP Strict Transport Security (HSTS) tells browsers to always use HTTPS for your site, preventing SSL stripping attacks where attackers downgrade connections to HTTP.",
        "severity": "high",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses. Test thoroughly before enabling preload.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://hstspreload.org/",
        ],
    },
    "missing-x-frame-options": {
        "explanation": "X-Frame-Controls whether your site can be embedded in iframes. Without it, attackers can embed your site in a hidden frame and trick users into clicking elements (clickjacking attacks).",
        "severity": "medium",
        "remediation": "Add X-Frame-Options: DENY to prevent all framing, or SAMEORIGIN to allow only same-site framing.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        ],
    },
    "missing-x-content-type-options": {
        "explanation": "X-Content-Type-Options prevents browsers from MIME-sniffing responses away from the declared content type. Without it, attackers might upload files that execute as scripts.",
        "severity": "low",
        "remediation": "Add X-Content-Type-Options: nosniff to all responses.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        ],
    },
    "missing-referrer-policy": {
        "explanation": "Referrer Policy controls how much referrer information is sent with requests. Without it, sensitive URL parameters might leak to third parties.",
        "severity": "low",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin to balance privacy and functionality.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        ],
    },
    "missing-permissions-policy": {
        "explanation": "Permissions Policy (formerly Feature Policy) controls which browser features (camera, microphone, geolocation) can be used on your site. Without it, embedded content might access sensitive APIs.",
        "severity": "low",
        "remediation": "Add Permissions-Policy with restrictive defaults: camera=(), microphone=(), geolocation=(), etc.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        ],
    },
    "no-https": {
        "explanation": "Your site doesn't use HTTPS, which means all data transmitted between users and your server is unencrypted and can be intercepted or modified by attackers.",
        "severity": "critical",
        "remediation": "Install an SSL/TLS certificate and redirect all HTTP traffic to HTTPS. Let's Encrypt provides free certificates.",
        "references": [
            "https://letsencrypt.org/",
            "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
        ],
    },
    "information-disclosure": {
        "explanation": "Your server is revealing technology information in HTTP headers. Attackers can use this to find known vulnerabilities for your specific software versions.",
        "severity": "low",
        "remediation": "Remove X-Powered-By headers from your server configuration. This doesn't prevent attacks but makes reconnaissance harder.",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
        ],
    },
    "server-version-exposed": {
        "explanation": "Your server software version is visible in the Server header. Attackers can look up CVEs for that specific version and craft targeted attacks.",
        "severity": "low",
        "remediation": "Configure your web server to hide version information. In nginx: server_tokens off; In Apache: ServerTokens Prod",
        "references": [
            "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",
            "https://httpd.apache.org/docs/current/mod/core.html#servertokens",
        ],
    },
    "insecure-form-action": {
        "explanation": "A form on your page submits to an HTTP URL. Even if your page is HTTPS, the form data will be sent unencrypted, exposing passwords and other sensitive data.",
        "severity": "high",
        "remediation": "Update all form actions to use HTTPS URLs. Also check that the form's action attribute uses https://",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/form",
        ],
    },
    "missing-csrf-protection": {
        "explanation": "A form that changes state (POST request) doesn't include a CSRF token. Attackers can trick users into submitting forms they didn't intend to, potentially changing passwords or making purchases.",
        "severity": "medium",
        "remediation": "Add CSRF tokens to all state-changing forms. Most web frameworks (Django, Rails, Laravel) have built-in CSRF protection.",
        "references": [
            "https://owasp.org/www-community/attacks/cs",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
}


async def connect_account() -> Dict[str, Any]:
    """
    Connect your CyberLens account for cloud-powered scanning.

    Opens a browser window to sign in or create a CyberLens account.
    Once authenticated, your API key is stored locally for future scans.

    Returns:
        Dictionary with connection status
    """
    try:
        existing = load_api_key()
        if existing:
            return {
                "success": True,
                "message": "Already connected to CyberLens.",
                "key_prefix": existing[:12] + "...",
                "hint": "Run this again to reconnect with a new key.",
            }

        key = await run_connect_flow()
        return {
            "success": True,
            "message": "Successfully connected to CyberLens!",
            "key_prefix": key[:12] + "...",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


async def scan_website(
    url: str,
    scan_depth: str = "standard",
    timeout: float = 30.0,
    use_cloud: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Perform a security scan on a website URL.

    Uses the CyberLens cloud API if connected (more thorough, 70+ checks).
    Falls back to local scanning if not connected.

    Args:
        url: The website URL to scan (must include https:// or http://)
        scan_depth: How thorough the scan should be ("quick", "standard", "deep")
        timeout: Request timeout in seconds
        use_cloud: Force cloud (True) or local (False) scanning. None = auto-detect.

    Returns:
        Dictionary with scan results including score, grade, and findings
    """
    api_key = load_api_key()
    should_use_cloud = use_cloud if use_cloud is not None else bool(api_key)

    if should_use_cloud and api_key:
        try:
            async with CyberLensAPIClient(api_key, timeout=timeout) as client:
                result = await client.scan(url)
                return {
                    "success": True,
                    "source": "cloud",
                    "url": result.get("url", url),
                    "score": result.get("scores", {}).get("overall", 0),
                    "grade": _score_to_grade(result.get("scores", {}).get("overall", 0)),
                    "findings_count": result.get("summary", {}).get("vulnerabilities_found", 0),
                    "summary": result.get("summary", {}),
                    "findings": [
                        {
                            "type": v.get("type", "unknown"),
                            "severity": v.get("severity", "info"),
                            "description": v.get("title", v.get("description", "")),
                        }
                        for v in (result.get("vulnerabilities", []) or [])[:10]
                    ],
                }
        except Exception as e:
            if use_cloud is True:
                return {"success": False, "error": f"Cloud scan failed: {e}", "url": url}
            # Fall through to local scan

    # Local scanning fallback
    async with SecurityScanner(timeout=timeout) as scanner:
        result = await scanner.scan(url)

        if result.error:
            return {"success": False, "error": result.error, "url": result.url}

        return {
            "success": True,
            "source": "local",
            "url": result.url,
            "score": result.score,
            "grade": result.grade,
            "scan_time_ms": result.scan_time_ms,
            "technologies": result.technologies,
            "findings_count": len(result.findings),
            "findings": [
                {
                    "type": f.type,
                    "severity": f.severity,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
        }


async def get_security_score(
    url: str,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """
    Quick security score check for a URL.

    Uses the CyberLens cloud API if connected, otherwise local scanning.

    Args:
        url: The website URL to check
        timeout: Request timeout in seconds

    Returns:
        Dictionary with score and grade
    """
    api_key = load_api_key()

    if api_key:
        try:
            async with CyberLensAPIClient(api_key, timeout=timeout) as client:
                result = await client.scan(url)
                score = result.get("scores", {}).get("overall", 0)
                grade = _score_to_grade(score)
                return {
                    "success": True,
                    "source": "cloud",
                    "url": url,
                    "score": score,
                    "grade": grade,
                    "assessment": _get_grade_assessment(grade),
                }
        except Exception:
            pass  # Fall through to local

    async with SecurityScanner(timeout=timeout) as scanner:
        score, grade = await scanner.get_score(url)
        return {
            "success": True,
            "source": "local",
            "url": url,
            "score": score,
            "grade": grade,
            "assessment": _get_grade_assessment(grade),
        }


def _score_to_grade(score: int) -> str:
    """Convert a numeric score to a letter grade."""
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def _get_grade_assessment(grade: str) -> str:
    """Get a human-readable assessment for a grade."""
    assessments = {
        "A": "Excellent security posture. Minor improvements possible.",
        "B": "Good security with some room for improvement.",
        "C": "Average security. Several issues should be addressed.",
        "D": "Below average. Significant security improvements needed.",
        "F": "Poor security. Critical issues must be fixed immediately.",
    }
    return assessments.get(grade, "Unknown grade")


def explain_finding(
    finding_type: str,
    context: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get a plain-English explanation of a security finding.
    
    Args:
        finding_type: The type of finding (e.g., "missing-csp", "no-https")
        context: Optional context about where the finding was detected
    
    Returns:
        Dictionary with explanation, severity, and remediation advice
    """
    explanation = FINDING_EXPLANATIONS.get(finding_type)
    
    if not explanation:
        return {
            "success": False,
            "error": f"Unknown finding type: {finding_type}",
            "known_types": list(FINDING_EXPLANATIONS.keys()),
        }
    
    result = {
        "success": True,
        "finding_type": finding_type,
        "explanation": explanation["explanation"],
        "severity": explanation["severity"],
        "remediation": explanation["remediation"],
        "references": explanation["references"],
    }
    
    if context:
        result["context"] = context
    
    return result


def list_scan_rules() -> Dict[str, Any]:
    """
    List all available scan rules/categories.
    
    Returns:
        Dictionary with available scan rules organized by category
    """
    categories = {
        "headers": {
            "description": "HTTP security header checks",
            "rules": [
                {"name": "content-security-policy", "severity": "medium"},
                {"name": "strict-transport-security", "severity": "high"},
                {"name": "x-frame-options", "severity": "medium"},
                {"name": "x-content-type-options", "severity": "low"},
                {"name": "referrer-policy", "severity": "low"},
                {"name": "permissions-policy", "severity": "low"},
            ],
        },
        "https": {
            "description": "HTTPS and TLS configuration checks",
            "rules": [
                {"name": "https-enforced", "severity": "critical"},
                {"name": "hsts-enabled", "severity": "high"},
            ],
        },
        "disclosure": {
            "description": "Information disclosure detection",
            "rules": [
                {"name": "server-header", "severity": "low"},
                {"name": "x-powered-by", "severity": "low"},
                {"name": "version-exposure", "severity": "low"},
            ],
        },
        "forms": {
            "description": "Form security analysis",
            "rules": [
                {"name": "csrf-protection", "severity": "medium"},
                {"name": "secure-form-action", "severity": "high"},
            ],
        },
    }
    
    total_rules = sum(len(cat["rules"]) for cat in categories.values())
    
    return {
        "success": True,
        "total_rules": total_rules,
        "categories": categories,
    }
