"""Tier 1: HTTP with TLS/JA3 impersonation. Cheap and fast."""
from dataclasses import dataclass

from curl_cffi.requests import AsyncSession

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

IMPERSONATE = "chrome"


class Blocked(Exception):
    """Raised so the router escalates rather than retrying the same tier."""


@dataclass
class Response:
    url: str
    status: int
    text: str
    tier: int
    headers: dict


async def fetch(url: str, timeout: int = 30) -> Response:
    async with AsyncSession(impersonate=IMPERSONATE) as s:
        r = await s.get(url, timeout=timeout,
                        headers={"User-Agent": UA,
                                 "Accept-Language": "en-US,en;q=0.9"})
    if r.status_code in (403, 429, 503):
        raise Blocked(f"{r.status_code} on {url}")
    if r.status_code >= 500:
        raise Blocked(f"{r.status_code} on {url}")
    return Response(url=url, status=r.status_code, text=r.text, tier=1,
                    headers=dict(r.headers))