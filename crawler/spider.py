"""
crawler/spider.py
Async spider that extracts forms, inputs, query params, and links
from target URLs. Supports configurable crawl depth.
"""

import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import List, Set, Dict, Tuple

from bs4 import BeautifulSoup

from utils.config import ScanTarget, ScanConfig, Context
from utils.http_client import HttpClient
from utils.logger import debug, progress, info


class Spider:
    """
    BFS-based async spider.

    Extracts:
    - GET parameters (from query string)
    - POST forms with all input fields
    - Linked pages (within same domain, up to depth)
    """

    def __init__(self, config: ScanConfig, http: HttpClient):
        self.config    = config
        self.http      = http
        self._visited: Set[str] = set()

    async def crawl(self, start_url: str) -> List[ScanTarget]:
        """
        Crawl start_url up to config.depth levels deep.
        Returns a deduplicated list of ScanTargets.
        """
        targets: List[ScanTarget] = []
        queue: deque[Tuple[str, int]] = deque([(start_url, 0)])
        base_domain = urlparse(start_url).netloc

        while queue:
            url, depth = queue.popleft()
            norm = self._normalize(url)
            if norm in self._visited:
                continue
            self._visited.add(norm)

            debug(f"Crawling [{depth}]: {url}")
            resp = await self.http.get(url)
            if resp is None or not resp.ok:
                continue

            # Extract targets on this page
            page_targets = self._extract_targets(url, resp.text)
            targets.extend(page_targets)

            if depth < self.config.depth:
                links = self._extract_links(url, resp.text, base_domain)
                for link in links:
                    if self._normalize(link) not in self._visited:
                        queue.append((link, depth + 1))

        info(f"Crawl complete — {len(targets)} injection points found across {len(self._visited)} pages")
        return self._deduplicate(targets)

    # ─── Extraction ──────────────────────────────────────────────────────────

    def _extract_targets(self, page_url: str, html: str) -> List[ScanTarget]:
        targets = []
        soup = BeautifulSoup(html, "html.parser")

        # 1. Query string parameters (GET)
        parsed = urlparse(page_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for key in params:
            targets.append(ScanTarget(
                url=page_url,
                method="GET",
                params={k: v[0] for k, v in params.items()},
                param_key=key,
                context=Context.UNKNOWN,
            ))

        # 2. HTML forms (GET + POST)
        for form in soup.find_all("form"):
            form_targets = self._parse_form(page_url, form)
            targets.extend(form_targets)

        # 3. Links with query params (additional GET params)
        for a in soup.find_all("a", href=True):
            href = urljoin(page_url, a["href"])
            p = urlparse(href)
            if p.query:
                params2 = parse_qs(p.query, keep_blank_values=True)
                for key in params2:
                    targets.append(ScanTarget(
                        url=href,
                        method="GET",
                        params={k: v[0] for k, v in params2.items()},
                        param_key=key,
                        context=Context.UNKNOWN,
                    ))

        return targets

    def _parse_form(self, page_url: str, form) -> List[ScanTarget]:
        """Extract all input points from an HTML form."""
        action = form.get("action", page_url)
        action = urljoin(page_url, action)
        method = (form.get("method", "GET")).upper()
        if method not in ("GET", "POST"):
            method = "GET"

        fields: Dict[str, str] = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name") or inp.get("id")
            if not name:
                continue
            itype = inp.get("type", "text").lower()
            if itype in ("submit", "button", "image", "reset", "hidden"):
                fields[name] = inp.get("value", "test")
            else:
                fields[name] = inp.get("value", "")

        targets = []
        for key in fields:
            if method == "POST":
                targets.append(ScanTarget(
                    url=action,
                    method="POST",
                    data=fields.copy(),
                    param_key=key,
                    context=Context.UNKNOWN,
                ))
            else:
                targets.append(ScanTarget(
                    url=action,
                    method="GET",
                    params=fields.copy(),
                    param_key=key,
                    context=Context.UNKNOWN,
                ))
        return targets

    def _extract_links(self, base: str, html: str, domain: str) -> List[str]:
        """Extract same-domain links."""
        soup  = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all(["a", "link"], href=True):
            href = urljoin(base, tag["href"])
            p = urlparse(href)
            if p.netloc == domain and p.scheme in ("http", "https"):
                links.append(href)
        return links

    # ─── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize(url: str) -> str:
        """Normalize URL for deduplication (strip fragment)."""
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))

    @staticmethod
    def _deduplicate(targets: List[ScanTarget]) -> List[ScanTarget]:
        """Remove duplicate (url, method, param_key) combinations."""
        seen  = set()
        clean = []
        for t in targets:
            key = (t.url, t.method, t.param_key)
            if key not in seen:
                seen.add(key)
                clean.append(t)
        return clean


# ─── Context Detector ─────────────────────────────────────────────────────────

class ContextDetector:
    """
    Detect the injection context of a reflection by sending a canary
    and analysing where it appears in the response.
    """

    CANARY = "xscnr7s3"

    async def detect(
        self,
        target: ScanTarget,
        http: HttpClient,
    ) -> str:
        """
        Send a canary value and determine the reflection context.
        Returns one of the Context constants.
        """
        # Inject canary
        test_target = self._inject_canary(target)
        if test_target.method == "GET":
            resp = await http.get(test_target.url, params=test_target.params)
        else:
            resp = await http.post(test_target.url, data=test_target.data)

        if resp is None:
            return Context.UNKNOWN

        return self._classify(resp.text)

    def _inject_canary(self, target: ScanTarget) -> ScanTarget:
        import copy
        t = copy.deepcopy(target)
        if t.method == "GET":
            t.params[t.param_key] = self.CANARY
        else:
            t.data[t.param_key] = self.CANARY
        return t

    def _classify(self, body: str) -> str:
        if self.CANARY not in body:
            return Context.UNKNOWN

        idx = body.index(self.CANARY)
        before = body[max(0, idx - 100):idx].lower()
        after  = body[idx + len(self.CANARY):idx + len(self.CANARY) + 50].lower()

        # Inside <script> tag
        if re.search(r"<script[^>]*>", before):
            if "'" in before.split("\n")[-1] or '"' in before.split("\n")[-1]:
                return Context.JS_STRING
            if "`" in before.split("\n")[-1]:
                return Context.JS_TEMPLATE
            return Context.JS

        # Inside HTML comment
        if "<!--" in before:
            return Context.COMMENT

        # Inside an attribute
        attr_match = re.search(r"<[\w]+", before)
        if attr_match:
            return Context.ATTRIBUTE

        # Inside style/css
        if re.search(r"<style[^>]*>", before) or re.search(r'style=["\'][^"\']*$', before):
            return Context.CSS

        # Default: HTML body
        return Context.HTML
