"""
utils/http_client.py
Async HTTP client with retry logic, proxy support, and rate limiting.
"""

import asyncio
import aiohttp
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse

from utils.config import DEFAULT_HEADERS, ScanConfig
from utils.logger import debug, warn


class HttpClient:
    """
    Async HTTP client wrapping aiohttp with:
    - Connection pooling
    - Automatic retry with exponential back-off
    - Optional proxy routing
    - Rate limiting
    - SSL verification bypass for test environments
    """

    def __init__(self, config: ScanConfig):
        self.config     = config
        self.timeout    = aiohttp.ClientTimeout(total=config.timeout)
        self._semaphore = asyncio.Semaphore(config.threads)
        self._last_req  = 0.0
        self._session: Optional[aiohttp.ClientSession] = None

        headers = {**DEFAULT_HEADERS, **config.headers}
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=config.threads * 2,
            force_close=False,
            enable_cleanup_closed=True,
        )
        self._session = aiohttp.ClientSession(
            headers=headers,
            connector=connector,
            timeout=self.timeout,
            cookies=config.cookies,
        )

    # ─── Public API ───────────────────────────────────────────────────────────

    async def get(self, url: str, params: Dict = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self._request("GET", url, params=params, **kwargs)

    async def post(self, url: str, data: Dict = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self._request("POST", url, data=data, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self._request(method, url, **kwargs)

    # ─── Core ─────────────────────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        url: str,
        retries: int = 3,
        **kwargs,
    ) -> Optional["ResponseWrapper"]:
        await self._rate_limit()

        proxy = self.config.proxy or None
        if proxy:
            kwargs["proxy"] = proxy

        async with self._semaphore:
            for attempt in range(retries):
                try:
                    async with self._session.request(method, url, **kwargs) as resp:
                        body = await resp.text(errors="replace")
                        headers = dict(resp.headers)
                        return ResponseWrapper(
                            status=resp.status,
                            url=str(resp.url),
                            text=body,
                            headers=headers,
                        )
                except asyncio.TimeoutError:
                    debug(f"Timeout on {url} (attempt {attempt+1}/{retries})")
                    if attempt < retries - 1:
                        await asyncio.sleep(2 ** attempt)
                except aiohttp.ClientError as e:
                    debug(f"Client error {url}: {e}")
                    break
                except Exception as e:
                    debug(f"Unexpected error {url}: {e}")
                    break
        return None

    async def _rate_limit(self):
        if self.config.rate_limit > 0:
            now = time.monotonic()
            elapsed = now - self._last_req
            if elapsed < self.config.rate_limit:
                await asyncio.sleep(self.config.rate_limit - elapsed)
            self._last_req = time.monotonic()

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()


class ResponseWrapper:
    """Lightweight wrapper around HTTP response data."""

    __slots__ = ("status", "url", "text", "headers")

    def __init__(self, status: int, url: str, text: str, headers: dict):
        self.status  = status
        self.url     = url
        self.text    = text
        self.headers = headers

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400
