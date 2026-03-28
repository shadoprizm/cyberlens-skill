"""CyberLens API client for cloud-powered scanning."""

import asyncio
import os
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx


DEFAULT_API_BASE = "https://api.cyberlensai.com/functions/v1/public-api-scan"


def _resolve_api_base(api_base: Optional[str] = None) -> str:
    """Resolve and validate the CyberLens API base URL."""
    candidate = (api_base or os.environ.get("CYBERLENS_API_BASE_URL") or DEFAULT_API_BASE).strip()
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("CyberLens API base URL must be a valid https:// URL.")
    return candidate.rstrip("/")


class CyberLensAPIClient:
    """Async client for the CyberLens public scan API."""

    def __init__(self, api_key: str, timeout: float = 120.0, api_base: Optional[str] = None):
        self.api_key = api_key
        self.timeout = timeout
        self.api_base = _resolve_api_base(api_base)
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            headers={
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
            },
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def start_scan(self, url: str) -> str:
        """Start a scan and return the scan ID."""
        response = await self._client.post(
            f"{self.api_base}/scan",
            json={"url": url},
        )
        response.raise_for_status()
        data = response.json()
        return data["data"]["scan_id"]

    async def poll_scan(self, scan_id: str) -> Dict[str, Any]:
        """Poll for scan results with exponential backoff."""
        delay = 1.0
        max_delay = 30.0
        elapsed = 0.0

        while elapsed < self.timeout:
            await asyncio.sleep(delay)
            elapsed += delay

            response = await self._client.get(f"{self.api_base}/scan/{scan_id}")
            response.raise_for_status()
            data = response.json()["data"]

            if data["status"] == "completed":
                return data
            if data["status"] == "failed":
                raise RuntimeError("Scan failed on the server.")

            delay = min(delay * 2, max_delay)

        raise TimeoutError("Scan timed out waiting for results.")

    async def scan(self, url: str) -> Dict[str, Any]:
        """Start a scan and wait for results."""
        scan_id = await self.start_scan(url)
        return await self.poll_scan(scan_id)

    async def get_quota(self) -> Dict[str, Any]:
        """Get current usage quota."""
        response = await self._client.get(f"{self.api_base}/quota")
        response.raise_for_status()
        return response.json()["data"]
