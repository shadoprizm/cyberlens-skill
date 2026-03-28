"""Tests for CyberLens API base URL resolution."""

import pytest

from src.api_client import CyberLensAPIClient, DEFAULT_API_BASE


def test_client_uses_default_api_base(monkeypatch):
    monkeypatch.delenv("CYBERLENS_API_BASE_URL", raising=False)

    client = CyberLensAPIClient("clns_acct_test")

    assert client.api_base == DEFAULT_API_BASE


def test_client_uses_env_api_base_override(monkeypatch):
    monkeypatch.setenv(
        "CYBERLENS_API_BASE_URL",
        "https://alt-api.cyberlensai.com/functions/v1/public-api-scan",
    )

    client = CyberLensAPIClient("clns_acct_test")

    assert client.api_base == "https://alt-api.cyberlensai.com/functions/v1/public-api-scan"


def test_client_rejects_non_https_api_base():
    with pytest.raises(ValueError, match="https:// URL"):
        CyberLensAPIClient(
            "clns_acct_test",
            api_base="http://localhost:8000/functions/v1/public-api-scan",
        )
