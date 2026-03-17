"""
scanner/engine.py
Core scanning engine — orchestrates crawling, payload injection,
WAF detection, and finding aggregation.
"""

import asyncio
import copy
from typing import List, Optional
from urllib.parse import urlencode, urlunparse, urlparse

from utils.config import ScanConfig, ScanTarget, Finding, Context, SCAN_PROFILES
from utils.http_client import HttpClient
from utils.logger import debug, info, progress, finding as log_finding, warn
from crawler.spider import Spider, ContextDetector
from payloads.generator import PayloadGenerator
from detection.analyzer import DetectionEngine
from waf_bypass.detector import WAFDetector, EvasionEngine


class ScanEngine:
    """
    Main orchestrator.

    Flow per target URL:
    1. Crawl  → collect ScanTargets
    2. Detect context per injection point
    3. Probe WAF
    4. Generate context-aware payloads (+ evasions if WAF detected)
    5. Inject and analyze responses
    6. Aggregate findings
    """

    def __init__(self, config: ScanConfig):
        self.config   = config
        self.http     = HttpClient(config)
        self._profile = SCAN_PROFILES.get(config.profile, SCAN_PROFILES["normal"])
        self.findings: List[Finding] = []
        self._lock    = asyncio.Lock()

        max_p = self._profile["payloads_per_ctx"]
        self.payload_gen  = PayloadGenerator(max_per_ctx=max_p, waf_bypass=config.waf_bypass)
        self.detector     = DetectionEngine()
        self.evasion      = EvasionEngine()
        self.ctx_detector = ContextDetector()
        self.waf_detector = WAFDetector()

    # ─── Public API ──────────────────────────────────────────────────────────

    async def run(self) -> List[Finding]:
        """Run scans for all configured targets concurrently."""
        tasks = [self._scan_url(url) for url in self.config.targets]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings

    async def scan_targets(self, targets: List[ScanTarget]) -> List[Finding]:
        """Scan a pre-built list of ScanTargets (used when caller provides targets directly)."""
        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._scan_one_with_sem(t, sem) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings

    # ─── Per-URL Flow ────────────────────────────────────────────────────────

    async def _scan_url(self, url: str):
        info(f"Starting scan: {url}")

        # 1. Crawl
        if self.config.crawl:
            spider  = Spider(self.config, self.http)
            targets = await spider.crawl(url)
        else:
            targets = self._url_to_targets(url)

        if not targets:
            warn(f"No injection points found at {url}")
            return

        info(f"Found {len(targets)} injection points")

        # 2. Detect WAF on base URL
        base_resp = await self.http.get(url)
        waf = self.waf_detector.detect(base_resp) if base_resp else None
        if waf:
            warn(f"WAF detected: {waf} — activating evasion strategies")

        # 3. Scan each target
        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._scan_one_with_sem(t, sem, waf=waf) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _scan_one_with_sem(
        self,
        target: ScanTarget,
        sem: asyncio.Semaphore,
        waf: Optional[str] = None,
    ):
        async with sem:
            await self._scan_one(target, waf=waf)

    async def _scan_one(self, target: ScanTarget, waf: Optional[str] = None):
        """Full injection test for one ScanTarget."""

        # Detect injection context
        context = await self.ctx_detector.detect(target, self.http)
        target.context = context
        debug(f"Context [{context}] — {target.url} param={target.param_key}")

        # Get baseline response length
        baseline_resp = await self._send(target)
        baseline_len  = len(baseline_resp.text) if baseline_resp else 0

        # Generate payloads for context
        payloads = self.payload_gen.for_context(context)

        # Add blind XSS payloads if callback configured
        if self.config.blind_callback:
            payloads += self.payload_gen.for_blind_xss(self.config.blind_callback)

        # Add WAF evasion variants
        if waf and self.config.waf_bypass:
            evasion_payloads = []
            for (p, enc) in payloads[:15]:
                for (ep, technique) in self.evasion.apply(p, waf):
                    evasion_payloads.append((ep, f"evasion:{technique}"))
            payloads = payloads + evasion_payloads

        # Test each payload
        for payload, encoding in payloads:
            await self._test_payload(target, payload, encoding, context, waf, baseline_len)

    async def _test_payload(
        self,
        target: ScanTarget,
        payload: str,
        encoding: str,
        context: str,
        waf: Optional[str],
        baseline_len: int,
    ):
        """Inject one payload and analyze the response."""
        injected = self._inject(target, payload)
        resp = await self._send(injected)
        if resp is None:
            return

        # Heuristic WAF block check
        if self.waf_detector.is_blocked(baseline_len, len(resp.text), resp.status):
            debug(f"Blocked [{resp.status}]: {payload[:50]}")
            return

        # Quick reflection pre-filter
        if not self.detector.quick_reflect(payload, resp.text):
            return

        # Full analysis
        result = self.detector.analyze(payload, resp.text, context, waf is not None)
        if result is None:
            return

        # Determine XSS type
        xss_type = self._classify_xss_type(target, result)

        f = Finding(
            url           = target.url,
            param         = target.param_key,
            payload       = payload,
            context       = context,
            xss_type      = xss_type,
            evidence      = result["evidence"],
            waf_bypassed  = waf is not None,
            severity      = result["severity"],
            confidence    = result["confidence"],
            encoding_used = encoding,
        )

        async with self._lock:
            # Deduplicate: skip if same url+param+context already found
            duplicate = any(
                existing.url == f.url and
                existing.param == f.param and
                existing.context == f.context
                for existing in self.findings
            )
            if not duplicate:
                self.findings.append(f)
                log_finding(f.url, f.param, f.payload, f.xss_type, f.context)

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _inject(self, target: ScanTarget, payload: str) -> ScanTarget:
        """Return a copy of target with payload injected into param_key."""
        t = copy.deepcopy(target)
        if t.method == "GET":
            t.params[t.param_key] = payload
        else:
            t.data[t.param_key] = payload
        return t

    async def _send(self, target: ScanTarget):
        if target.method == "GET":
            return await self.http.get(target.url, params=target.params)
        else:
            return await self.http.post(target.url, data=target.data)

    def _classify_xss_type(self, target: ScanTarget, result: dict) -> str:
        if result.get("dom_vuln") and not result.get("executable"):
            return "dom"
        if target.method == "POST":
            return "stored"
        return "reflected"

    def _url_to_targets(self, url: str) -> List[ScanTarget]:
        """Parse query params from URL into individual ScanTargets."""
        parsed = urlparse(url)
        from urllib.parse import parse_qs
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []
        targets = []
        base_params = {k: v[0] for k, v in params.items()}
        for key in params:
            targets.append(ScanTarget(
                url=url,
                method="GET",
                params=base_params.copy(),
                param_key=key,
                context=Context.UNKNOWN,
            ))
        return targets

    async def close(self):
        await self.http.close()
