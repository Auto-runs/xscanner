"""
scanner/blind_server.py
Lightweight asyncio HTTP server that listens for blind XSS callbacks.
Logs any incoming request as a potential blind XSS execution.
"""

import asyncio
from aiohttp import web
from utils.logger import finding, info, warn
from utils.config import Context


class BlindXSSServer:
    """
    Start a local HTTP server on a chosen port.
    Any request that arrives is logged as a blind XSS hit.

    Usage:
        server = BlindXSSServer(port=8765)
        await server.start()
        # ... scan runs ...
        await server.stop()
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self._runner: web.AppRunner = None
        self.hits: list = []

    async def start(self):
        app = web.Application()
        app.router.add_route("*", "/{path_info:.*}", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        info(f"Blind XSS callback server listening on http://{self.host}:{self.port}")

    async def _handle(self, request: web.Request) -> web.Response:
        headers = dict(request.headers)
        params  = dict(request.rel_url.query)
        body    = await request.text()

        hit = {
            "path":    str(request.rel_url),
            "method":  request.method,
            "ip":      request.remote,
            "headers": headers,
            "params":  params,
            "body":    body[:500],
        }
        self.hits.append(hit)

        # Log as finding
        finding(
            url     = f"http://{self.host}:{self.port}{request.rel_url}",
            param   = "blind_callback",
            payload = f"Blind callback received — data: {params}",
            xss_type= "blind_xss",
            context = Context.UNKNOWN,
        )
        return web.Response(text="OK", status=200)

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
            info(f"Blind XSS server stopped. Total hits: {len(self.hits)}")
