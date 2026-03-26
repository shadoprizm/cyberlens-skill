"""CyberLens API client for cloud-powered scanning."""

import asyncio
from typing import Any, Dict, Optional

import httpx


API_BASE = "https://phodfgfegbwkjhgsdyhc.supabase.co/functions/v1/public-api-scan"


class CyberLensAPIClient:
    """Async client for the CyberLens public scan API."""

    def __init__(self, api_key: str, timeout: float = 120.0):
        self.api_key = api_key
        self.timeout = timeout
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
            f"{API_BASE}/scan",
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

            response = await self._client.get(f"{API_BASE}/scan/{scan_id}")
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
        response = await self._client.get(f"{API_BASE}/quota")
        response.raise_for_status()
        return response.json()["data"]
