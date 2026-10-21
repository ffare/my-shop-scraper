"""Smoke test: one URL through the full spine. Usage:
    python -m src.smoke <url>
"""
import asyncio
import sys

from src import extract
from src.router import Router


async def main(url: str):
    router = Router()
    cfg = router.cfg_for(url)
    if cfg is None:
        sys.exit(f"no site config for {url} - check config/sites.yaml")

    print(f"domain   : {cfg.domain}")
    print(f"tier     : {cfg.tier}")
    print(f"platform : {cfg.platform}")
    print(f"delay    : {cfg.delay_s}s  concurrency={cfg.concurrency}")
    print("-" * 60)

    resp, cfg = await router.fetch(url)
    print(f"status   : {resp.status}")
    print(f"tier used: {resp.tier}")
    print(f"bytes    : {len(resp.text):,}")
    print("-" * 60)

    fields, method = extract.extract(resp.text, cfg, url)
    print(f"extract  : {method}")
    if fields:
        for k, v in list(fields.items())[:20]:
            print(f"  {k}: {str(v)[:110]}")
    else:
        print("  (nothing extracted)")


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://www.mytek.tn/"
    asyncio.run(main(url))