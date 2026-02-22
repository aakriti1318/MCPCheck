"""
HTTP adapter for MCPCheck.

Handles fetching remote manifests, verifying schema URLs, etc.
"""

from __future__ import annotations

import hashlib
from typing import Any

import httpx


class HttpAdapter:
    """
    Adapter for HTTP operations.

    Uses httpx for async-first HTTP with HTTP/2 support.
    """

    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize the HTTP adapter.

        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    async def fetch_json(self, url: str) -> dict[str, Any]:
        """
        Fetch and parse JSON from a URL.

        Args:
            url: URL to fetch.

        Returns:
            Parsed JSON data.

        Raises:
            httpx.HTTPError: If request fails.
        """
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()

    async def fetch_text(self, url: str) -> str:
        """
        Fetch text content from a URL.

        Args:
            url: URL to fetch.

        Returns:
            Response text.
        """
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text

    async def verify_url(self, url: str) -> tuple[bool, str | None]:
        """
        Verify that a URL is reachable.

        Args:
            url: URL to verify.

        Returns:
            Tuple of (is_valid, error_message).
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
            ) as client:
                response = await client.head(url)
                response.raise_for_status()
                return (True, None)
        except httpx.HTTPError as e:
            return (False, str(e))

    async def fetch_with_hash(self, url: str) -> tuple[str, str]:
        """
        Fetch content and compute its SHA-256 hash.

        Useful for schema pinning verification.

        Args:
            url: URL to fetch.

        Returns:
            Tuple of (content, sha256_hash).
        """
        content = await self.fetch_text(url)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        return (content, content_hash)

    def fetch_json_sync(self, url: str) -> dict[str, Any]:
        """
        Synchronous version of fetch_json.

        Args:
            url: URL to fetch.

        Returns:
            Parsed JSON data.
        """
        with httpx.Client(
            timeout=self.timeout,
            verify=self.verify_ssl,
        ) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.json()
