"""Tests for CyberLens skill tools."""

import pytest
from src.tools import (
    explain_finding,
    list_scan_rules,
    _get_grade_assessment,
)


class TestExplainFinding:
    """Tests for explain_finding tool."""
    
    def test_explain_known_finding(self):
        """Test explaining a known finding type."""
        result = explain_finding("missing-csp")
        
        assert result["success"] is True
        assert result["finding_type"] == "missing-csp"
        assert "explanation" in result
        assert "severity" in result
        assert "remediation" in result
        assert "references" in result
        assert len(result["references"]) > 0
    
    def test_explain_with_context(self):
        """Test explaining with context."""
        context = "Detected on login page"
        result = explain_finding("missing-csp", context=context)
        
        assert result["success"] is True
        assert result["context"] == context
    
    def test_explain_unknown_finding(self):
        """Test explaining an unknown finding type."""
        result = explain_finding("unknown-finding-type")
        
        assert result["success"] is False
        assert "error" in result
        assert "known_types" in result
        assert "missing-csp" in result["known_types"]
    
    def test_all_severity_levels_present(self):
        """Verify all severity levels have explanations."""
        critical = explain_finding("no-https")
        assert critical["severity"] == "critical"
        
        high = explain_finding("missing-hsts")
        assert high["severity"] == "high"
        
        medium = explain_finding("missing-csp")
        assert medium["severity"] == "medium"
        
        low = explain_finding("information-disclosure")
        assert low["severity"] == "low"


class TestListScanRules:
    """Tests for list_scan_rules tool."""
    
    def test_returns_success(self):
        """Test that list_scan_rules returns success."""
        result = list_scan_rules()
        
        assert result["success"] is True
        assert "total_rules" in result
        assert "categories" in result
    
    def test_has_categories(self):
        """Test that categories are present."""
        result = list_scan_rules()
        categories = result["categories"]
        
        assert "headers" in categories
        assert "https" in categories
        assert "disclosure" in categories
        assert "forms" in categories
    
    def test_headers_category_has_rules(self):
        """Test headers category has expected rules."""
        result = list_scan_rules()
        headers = result["categories"]["headers"]
        
        assert "description" in headers
        assert "rules" in headers
        
        rule_names = [r["name"] for r in headers["rules"]]
        assert "content-security-policy" in rule_names
        assert "strict-transport-security" in rule_names
    
    def test_total_rules_matches(self):
        """Test total_rules matches actual rule count."""
        result = list_scan_rules()
        total = result["total_rules"]
        
        calculated = sum(
            len(cat["rules"])
            for cat in result["categories"].values()
        )
        
        assert total == calculated


class TestGetGradeAssessment:
    """Tests for grade assessment helper."""
    
    def test_all_grades_have_assessments(self):
        """Test all valid grades return assessments."""
        for grade in ["A", "B", "C", "D", "F"]:
            assessment = _get_grade_assessment(grade)
            assert len(assessment) > 0
            assert "Excellent" in assessment or "Good" in assessment or "Average" in assessment or "Below" in assessment or "Poor" in assessment
    
    def test_unknown_grade(self):
        """Test unknown grade returns default."""
        assessment = _get_grade_assessment("Z")
        assert "Unknown" in assessment


@pytest.mark.asyncio
class TestScanWebsite:
    """Tests for scan_website async tool."""
    
    async def test_scan_valid_https_site(self):
        """Test scanning a valid HTTPS site."""
        from src.tools import scan_website
        
        result = await scan_website("https://httpbin.org/get")
        
        assert result["success"] is True
        assert "url" in result
        assert "score" in result
        assert "grade" in result
        assert isinstance(result["score"], int)
        assert 0 <= result["score"] <= 100
        assert result["grade"] in ["A", "B", "C", "D", "F"]
    
    async def test_scan_invalid_url(self):
        """Test scanning an invalid URL."""
        from src.tools import scan_website
        
        result = await scan_website("not-a-valid-url")
        
        assert result["success"] is False
        assert "error" in result
    
    async def test_scan_missing_scheme(self):
        """Test URL without scheme returns error."""
        from src.tools import scan_website
        
        result = await scan_website("example.com")
        
        assert result["success"] is False
        assert "error" in result
    
    async def test_scan_with_timeout(self):
        """Test scan respects timeout parameter."""
        from src.tools import scan_website
        
        result = await scan_website("https://httpbin.org/delay/10", timeout=0.1)
        
        assert result["success"] is False
        assert "timeout" in result["error"].lower()


@pytest.mark.asyncio
class TestGetSecurityScore:
    """Tests for get_security_score async tool."""
    
    async def test_get_score_returns_data(self):
        """Test get_security_score returns expected fields."""
        from src.tools import get_security_score
        
        result = await get_security_score("https://httpbin.org/get")
        
        assert result["success"] is True
        assert "url" in result
        assert "score" in result
        assert "grade" in result
        assert "assessment" in result
    
    async def test_score_matches_grade(self):
        """Test score and grade are consistent."""
        from src.tools import get_security_score
        
        result = await get_security_score("https://httpbin.org/get")
        score = result["score"]
        grade = result["grade"]
        
        if score >= 90:
            assert grade == "A"
        elif score >= 80:
            assert grade == "B"
        elif score >= 70:
            assert grade == "C"
        elif score >= 60:
            assert grade == "D"
        else:
            assert grade == "F"
