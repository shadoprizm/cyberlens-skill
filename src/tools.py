"""Tool function implementations for OpenClaw integration."""

from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
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


GITHUB_RESERVED_PATHS = {
    "about",
    "account",
    "apps",
    "collections",
    "contact",
    "customer-stories",
    "enterprise",
    "events",
    "explore",
    "features",
    "gist",
    "gists",
    "issues",
    "login",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "organizations",
    "pricing",
    "pulls",
    "search",
    "security",
    "settings",
    "site",
    "sponsors",
    "topics",
    "trending",
    "users",
}


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


def _validate_target_url(target: str) -> Optional[str]:
    """Validate that the provided target is an HTTP(S) URL."""
    if not target.startswith(("http://", "https://")):
        return "URL must start with http:// or https://"

    parsed = urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        return "URL must include a valid hostname"

    return None


def _classify_target(target: str) -> str:
    """Classify a scan target as a website or GitHub repository URL."""
    validation_error = _validate_target_url(target)
    if validation_error:
        return "invalid"

    parsed = urlparse(target)
    host = parsed.netloc.lower()
    path_parts = [part for part in parsed.path.split("/") if part]

    if host in {"github.com", "www.github.com"} and len(path_parts) >= 2:
        owner = path_parts[0].lower()
        repo = path_parts[1]
        if owner not in GITHUB_RESERVED_PATHS and repo:
            return "repository"

    return "website"


def _normalize_cloud_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize website vulnerability payloads from the CyberLens cloud API."""
    return [
        {
            "test_id": vulnerability.get("testId") or vulnerability.get("type", "unknown"),
            "type": vulnerability.get("testId") or vulnerability.get("type", "unknown"),
            "severity": vulnerability.get("severity", "info"),
            "message": vulnerability.get("message") or vulnerability.get("title") or vulnerability.get("description", ""),
            "description": vulnerability.get("message") or vulnerability.get("title") or vulnerability.get("description", ""),
            "details": vulnerability.get("details") or vulnerability.get("description", ""),
            "recommendation": vulnerability.get("recommendation", ""),
            "passed": bool(vulnerability.get("passed", False)),
        }
        for vulnerability in vulnerabilities
    ]


def _flatten_repository_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten repository scan sections into a single findings list."""
    findings: List[Dict[str, Any]] = []

    for finding in result.get("security_findings", []) or []:
        findings.append({
            "source_section": "security_findings",
            "type": finding.get("test_id") or finding.get("category") or "repository-security-finding",
            "test_id": finding.get("test_id"),
            "severity": finding.get("severity", "info"),
            "confidence": finding.get("confidence"),
            "message": finding.get("message", ""),
            "description": finding.get("details") or finding.get("message", ""),
            "details": finding.get("details"),
            "recommendation": finding.get("recommendation"),
            "category": finding.get("category"),
            "cve": finding.get("cve"),
        })

    for finding in result.get("dependency_vulnerabilities", []) or []:
        package_name = finding.get("package_name", "unknown")
        current_version = finding.get("current_version", "unknown")
        findings.append({
            "source_section": "dependency_vulnerabilities",
            "type": "dependency-vulnerability",
            "severity": finding.get("severity", "info"),
            "message": f"{package_name}@{current_version} may have vulnerabilities",
            "description": finding.get("remediation", ""),
            "details": f"Current version: {current_version}",
            "recommendation": finding.get("remediation"),
            "package_name": package_name,
            "current_version": current_version,
            "patched_version": finding.get("patched_version"),
            "cve_ids": finding.get("cve_ids", []),
        })

    for finding in result.get("trust_posture_findings", []) or []:
        findings.append({
            "source_section": "trust_posture_findings",
            "type": "trust-posture",
            "severity": finding.get("severity", "info"),
            "message": finding.get("title") or finding.get("message", ""),
            "description": finding.get("message", ""),
            "details": finding.get("message"),
            "recommendation": finding.get("remediation"),
            "classification": finding.get("classification"),
        })

    for section_name in (
        "secret_findings",
        "behavioral_findings",
        "malicious_code_findings",
        "malicious_package_findings",
        "artifact_findings",
    ):
        for finding in result.get(section_name, []) or []:
            findings.append({
                "source_section": section_name,
                "type": finding.get("type") or finding.get("title") or section_name.rstrip("s"),
                "severity": finding.get("severity", "info"),
                "message": finding.get("message") or finding.get("title", ""),
                "description": finding.get("details") or finding.get("message") or finding.get("title", ""),
                "details": finding.get("details"),
                "recommendation": finding.get("recommendation") or finding.get("remediation"),
            })

    return findings


def _is_repository_scan_result(result: Dict[str, Any]) -> bool:
    """Return True when a cloud result matches the repository assessment schema."""
    return result.get("report_type") == "repository_security_assessment" or any(
        key in result
        for key in (
            "security_findings",
            "dependency_vulnerabilities",
            "trust_posture_findings",
            "repository",
        )
    )


def _format_repository_cloud_result(result: Dict[str, Any], target: str) -> Dict[str, Any]:
    """Format a repository assessment response from the CyberLens cloud API."""
    security_score = result.get("security_score", 0) or 0
    grade = _score_to_grade(security_score)
    findings = _flatten_repository_findings(result)
    findings_count = result.get("summary", {}).get("total_findings")
    if not isinstance(findings_count, int):
        findings_count = len(findings)

    return {
        "success": True,
        "source": "cloud",
        "target_type": "repository",
        "url": result.get("target", target),
        "score": security_score,
        "security_score": security_score,
        "trust_score": result.get("trust_score"),
        "grade": grade,
        "assessment": _get_grade_assessment(grade),
        "report_type": result.get("report_type", "repository_security_assessment"),
        "generated_at": result.get("generated_at"),
        "scan_date": result.get("scan_date"),
        "scan_type": result.get("scan_type"),
        "findings_count": findings_count,
        "summary": result.get("summary", {}),
        "repository": result.get("repository", {}),
        "ai_analysis": result.get("ai_analysis"),
        "findings": findings,
        "security_findings": result.get("security_findings", []),
        "dependency_vulnerabilities": result.get("dependency_vulnerabilities", []),
        "trust_posture_findings": result.get("trust_posture_findings", []),
        "secret_findings": result.get("secret_findings", []),
        "behavioral_findings": result.get("behavioral_findings", []),
        "malicious_code_findings": result.get("malicious_code_findings", []),
        "malicious_package_findings": result.get("malicious_package_findings", []),
        "artifact_findings": result.get("artifact_findings", []),
    }


def _format_website_cloud_result(result: Dict[str, Any], target: str) -> Dict[str, Any]:
    """Format a website scan response from the CyberLens cloud API."""
    vulnerabilities = result.get("vulnerabilities", []) or []
    findings_count = result.get("summary", {}).get("vulnerabilities_found")
    if not isinstance(findings_count, int):
        findings_count = len(vulnerabilities)

    return {
        "success": True,
        "source": "cloud",
        "target_type": "website",
        "url": result.get("url", target),
        "score": result.get("scores", {}).get("overall", 0),
        "grade": _score_to_grade(result.get("scores", {}).get("overall", 0)),
        "scan_type": result.get("scan_type"),
        "started_at": result.get("started_at"),
        "completed_at": result.get("completed_at"),
        "findings_count": findings_count,
        "summary": result.get("summary", {}),
        "ssl_info": result.get("ssl_info", {}),
        "headers_analysis": result.get("headers_analysis", {}),
        "database_passive_results": result.get("database_passive_results", []),
        "ai_insights": result.get("ai_insights"),
        "findings": _normalize_cloud_vulnerabilities(vulnerabilities),
    }


def _format_cloud_scan_result(result: Dict[str, Any], target: str) -> Dict[str, Any]:
    """Format a CyberLens cloud result for either websites or repositories."""
    if _is_repository_scan_result(result):
        return _format_repository_cloud_result(result, target)
    return _format_website_cloud_result(result, target)


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


async def scan_target(
    target: str,
    scan_depth: str = "standard",
    timeout: float = 30.0,
    use_cloud: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Scan a live website or GitHub repository URL.

    Website targets can use the CyberLens cloud API or the local fallback engine.
    GitHub repository targets use the CyberLens cloud API and require an account.

    Args:
        target: Website URL or GitHub repository URL
        scan_depth: How thorough the scan should be ("quick", "standard", "deep")
        timeout: Request timeout in seconds
        use_cloud: Force cloud (True) or local (False) scanning. None = auto-detect.

    Returns:
        Dictionary with scan results tailored to the detected target type
    """
    validation_error = _validate_target_url(target)
    if validation_error:
        return {"success": False, "error": validation_error, "url": target}

    target_type = _classify_target(target)
    api_key = load_api_key()
    should_use_cloud = use_cloud if use_cloud is not None else bool(api_key)

    if target_type == "repository":
        if not (should_use_cloud and api_key):
            return {
                "success": False,
                "target_type": "repository",
                "url": target,
                "error": (
                    "Repository scanning requires a connected CyberLens account. "
                    "Run connect_account or set CYBERLENS_API_KEY."
                ),
            }

        try:
            async with CyberLensAPIClient(api_key, timeout=timeout) as client:
                result = await client.scan(target)
                return _format_cloud_scan_result(result, target)
        except Exception as e:
            return {
                "success": False,
                "target_type": "repository",
                "url": target,
                "error": f"Cloud repository scan failed: {e}",
            }

    if should_use_cloud and api_key:
        try:
            async with CyberLensAPIClient(api_key, timeout=timeout) as client:
                result = await client.scan(target)
                return _format_cloud_scan_result(result, target)
        except Exception as e:
            if use_cloud is True:
                return {
                    "success": False,
                    "target_type": "website",
                    "error": f"Cloud scan failed: {e}",
                    "url": target,
                }
            # Fall through to local website scan

    async with SecurityScanner(timeout=timeout) as scanner:
        result = await scanner.scan(target)

        if result.error:
            return {
                "success": False,
                "target_type": "website",
                "error": result.error,
                "url": result.url,
            }

        return {
            "success": True,
            "source": "local",
            "target_type": "website",
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
    return await scan_target(
        target=url,
        scan_depth=scan_depth,
        timeout=timeout,
        use_cloud=use_cloud,
    )


async def scan_repository(
    repository_url: str,
    timeout: float = 60.0,
    use_cloud: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Scan a GitHub repository URL with CyberLens cloud analysis.

    Args:
        repository_url: GitHub repository URL such as https://github.com/owner/repo
        timeout: Request timeout in seconds
        use_cloud: Force cloud behavior. Repository scanning requires cloud access.

    Returns:
        Dictionary with repository security findings, scores, and summary
    """
    if _classify_target(repository_url) != "repository":
        return {
            "success": False,
            "error": (
                "Repository URL must be a GitHub repository URL like "
                "https://github.com/owner/repo"
            ),
            "url": repository_url,
        }

    return await scan_target(
        target=repository_url,
        timeout=timeout,
        use_cloud=use_cloud,
    )


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
    validation_error = _validate_target_url(url)
    if validation_error:
        return {"success": False, "error": validation_error, "url": url}

    target_type = _classify_target(url)
    api_key = load_api_key()

    if target_type == "repository":
        if not api_key:
            return {
                "success": False,
                "target_type": "repository",
                "url": url,
                "error": (
                    "Repository scoring requires a connected CyberLens account. "
                    "Run connect_account or set CYBERLENS_API_KEY."
                ),
            }

        try:
            async with CyberLensAPIClient(api_key, timeout=timeout) as client:
                result = await client.scan(url)
                score = result.get("security_score", 0) or 0
                grade = _score_to_grade(score)
                return {
                    "success": True,
                    "source": "cloud",
                    "target_type": "repository",
                    "url": result.get("target", url),
                    "score": score,
                    "security_score": score,
                    "trust_score": result.get("trust_score"),
                    "grade": grade,
                    "assessment": _get_grade_assessment(grade),
                }
        except Exception as e:
            return {
                "success": False,
                "target_type": "repository",
                "url": url,
                "error": f"Cloud repository scoring failed: {e}",
            }

    if api_key:
        try:
            async with CyberLensAPIClient(api_key, timeout=timeout) as client:
                result = await client.scan(url)
                score = result.get("scores", {}).get("overall", 0)
                grade = _score_to_grade(score)
                return {
                    "success": True,
                    "source": "cloud",
                    "target_type": "website",
                    "url": url,
                    "score": score,
                    "grade": grade,
                    "assessment": _get_grade_assessment(grade),
                }
        except Exception:
            pass  # Fall through to local

    async with SecurityScanner(timeout=timeout) as scanner:
        result = await scanner.scan(url)
        if result.error:
            return {
                "success": False,
                "target_type": "website",
                "url": result.url,
                "error": result.error,
            }

        return {
            "success": True,
            "source": "local",
            "target_type": "website",
            "url": result.url,
            "score": result.score,
            "grade": result.grade,
            "assessment": _get_grade_assessment(result.grade),
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
        "repository": {
            "description": "Cloud repository scanning categories for GitHub repositories and OpenClaw skills",
            "rules": [
                {"name": "dependency-vulnerabilities", "severity": "high"},
                {"name": "trust-posture", "severity": "medium"},
                {"name": "secret-detection", "severity": "high"},
                {"name": "malicious-package-review", "severity": "high"},
            ],
        },
    }
    
    total_rules = sum(len(cat["rules"]) for cat in categories.values())
    
    return {
        "success": True,
        "total_rules": total_rules,
        "categories": categories,
    }
