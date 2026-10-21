"""Tier 3: FlareSolverr. Needs the docker container on :8191."""
import httpx

from src.fetch_t1 import Blocked, Response

FLARESOLVERR = "http://127.0.0.1:8191/v1"


async def fetch(url: str, timeout: int = 60_000) -> Response:
    payload = {"cmd": "request.get", "url": url, "maxTimeout": timeout}
    async with httpx.AsyncClient(timeout=timeout / 1000 + 10) as c:
        r = await c.post(FLARESOLVERR, json=payload)
    data = r.json()
    if data.get("status") != "ok":
        raise Blocked(f"flaresolverr: {data.get('message')}")
    sol = data["solution"]
    status = sol.get("status", 0)
    if status in (403, 429, 503):
        raise Blocked(f"{status} on {url}")
    return Response(url=url, status=status, text=sol.get("response", ""),
                    tier=3, headers=sol.get("headers", {}))