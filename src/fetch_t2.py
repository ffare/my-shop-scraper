"""Tier 2: stealth browser. One camoufox instance per fetch (simple, correct)."""
from dataclasses import dataclass

from src.fetch_t1 import Blocked, Response


async def fetch(url: str, timeout: int = 45_000) -> Response:
    from camoufox.async_api import AsyncCamoufox

    async with AsyncCamoufox(headless=True) as browser:
        page = await browser.new_page()
        try:
            r = await page.goto(url, timeout=timeout,
                                wait_until="domcontentloaded")
            status = r.status if r else 0
            if status in (403, 429, 503) or status >= 500:
                raise Blocked(f"{status} on {url}")
            return Response(url=url, status=status, text=await page.content(),
                            tier=2, headers=dict(r.headers) if r else {})
        finally:
            await page.close()