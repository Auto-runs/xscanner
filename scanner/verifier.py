"""
scanner/verifier.py
Headless browser-based XSS verification using Playwright.
Confirms actual JavaScript execution, not just string reflection.

Requires: playwright install chromium
"""

import asyncio
from typing import Optional, List, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from utils.config import ScanTarget, Finding
from utils.logger import debug, success, warn


class HeadlessVerifier:
    """
    Uses a headless Chromium browser to verify XSS findings.

    For each Finding:
    1. Navigate to the URL with payload injected
    2. Listen for dialog events (alert/confirm/prompt)
    3. Mark finding as verified=True if dialog fires
    """

    def __init__(self, timeout_ms: int = 8000):
        self.timeout_ms = timeout_ms
        self._playwright = None
        self._browser    = None

    async def start(self):
        try:
            from playwright.async_api import async_playwright
            self._pw_ctx  = async_playwright()
            self._playwright = await self._pw_ctx.__aenter__()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            debug("Headless browser started")
        except ImportError:
            warn("Playwright not installed. Run: pip install playwright && playwright install chromium")
            self._browser = None

    async def verify(self, finding: Finding) -> bool:
        """
        Returns True if XSS execution is confirmed in headless browser.
        """
        if self._browser is None:
            return False

        url = self._build_url(finding)
        triggered = False

        try:
            page = await self._browser.new_page()
            page.set_default_timeout(self.timeout_ms)

            # Intercept dialogs (alert/confirm/prompt = XSS confirmed)
            async def on_dialog(dialog):
                nonlocal triggered
                triggered = True
                debug(f"Dialog triggered: type={dialog.type} msg={dialog.message[:50]}")
                await dialog.dismiss()

            page.on("dialog", on_dialog)

            await page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)

            # Also check for DOM mutations that indicate payload execution
            if not triggered:
                triggered = await page.evaluate(
                    "() => window.__xss_triggered === true"
                )

            await page.close()

        except Exception as e:
            debug(f"Headless verify error: {e}")

        return triggered

    async def verify_all(self, findings: List[Finding]) -> List[Finding]:
        """Verify a batch of findings. Updates finding.verified in-place."""
        if self._browser is None:
            return findings

        sem = asyncio.Semaphore(3)

        async def _verify_one(f: Finding):
            async with sem:
                result = await self.verify(f)
                if result:
                    f.verified = True
                    success(f"✓ Verified: {f.url} param={f.param}")

        await asyncio.gather(*[_verify_one(f) for f in findings])
        return findings

    async def stop(self):
        if self._browser:
            await self._browser.close()
        if self._playwright:
            try:
                await self._pw_ctx.__aexit__(None, None, None)
            except Exception:
                pass

    def _build_url(self, finding: Finding) -> str:
        """Inject the payload back into the URL for browser navigation."""
        parsed = urlparse(finding.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[finding.param] = [finding.payload]

        flat_params = {k: v[0] for k, v in params.items()}
        new_query   = urlencode(flat_params)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, ""
        ))
