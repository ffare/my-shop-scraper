"""Tier 2: stealth browser. One camoufox instance per fetch (simple, correct).

fetch(url, capture=[...]) additionally records the JSON responses the page
loads (XHR/fetch), so the checker can discover a site's backend API from what
the page itself requests. Without `capture` the behavior is unchanged.
"""
import asyncio
from dataclasses import dataclass

from src.fetch_t1 import Blocked, Response

MAX_CAPTURED = 40          # JSON responses kept per page
MAX_BODY = 2_000_000       # characters kept per response


async def _collect(responses, capture):
    added = 0
    for resp in responses:
        if added >= MAX_CAPTURED:
            break
        try:
            req = resp.request
            if req.resource_type not in ("xhr", "fetch"):
                continue
            if "json" not in (resp.headers.get("content-type") or "").lower():
                continue
            body = await resp.text()
            capture.append({"url": resp.url, "method": req.method,
                            "status": resp.status, "text": body[:MAX_BODY]})
            added += 1
        except Exception:
            continue          # body unavailable (redirect, aborted, ...)


async def fetch(url: str, timeout: int = 45_000,
                capture: list | None = None) -> Response:
    from camoufox.async_api import AsyncCamoufox

    responses = []
    async with AsyncCamoufox(headless=True) as browser:
        page = await browser.new_page()
        if capture is not None:
            page.on("response", lambda resp: responses.append(resp))
        try:
            r = await page.goto(url, timeout=timeout,
                                wait_until="domcontentloaded")
            status = r.status if r else 0
            if status in (403, 429, 503) or status >= 500:
                raise Blocked(f"{status} on {url}")
            if capture is not None:
                try:
                    await page.wait_for_load_state("networkidle",
                                                   timeout=15_000)
                except Exception:
                    pass                  # keep whatever has loaded so far
                await asyncio.sleep(1.0)
                await _collect(responses, capture)
            return Response(url=url, status=status, text=await page.content(),
                            tier=2, headers=dict(r.headers) if r else {})
        finally:
            await page.close()