"""CyberLens OpenClaw Skill - Website Security Scanner"""

__version__ = "0.1.0"
__author__ = "shadoprizm"

from .scanner import SecurityScanner
from .tools import (
    scan_website,
    get_security_score,
    explain_finding,
    list_scan_rules,
)
from .models import (
    ScanResult,
    SecurityScore,
    Finding,
    FindingExplanation,
    ScanRule,
)

__all__ = [
    "SecurityScanner",
    "scan_website",
    "get_security_score",
    "explain_finding",
    "list_scan_rules",
    "ScanResult",
    "SecurityScore",
    "Finding",
    "FindingExplanation",
    "ScanRule",
]
