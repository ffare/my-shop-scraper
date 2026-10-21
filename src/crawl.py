"""Crawl worker loop. Usage: python -m src.crawl -w 4 --limit 20"""
import argparse
import asyncio
import gzip
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from src import api, db, extract
from src.queue import Queue
from src.router import Router

RAW_DIR = Path("data/raw")

LOC = re.compile(r"<loc>\s*(?:<!\[CDATA\[)?\s*(.*?)\s*(?:\]\]>)?\s*</loc>", re.S)
SKIP_SITEMAPS = re.compile(r"sitemap_(categories|cms)\.xml")


def parse_sitemap(xml: str) -> tuple[bool, list[str]]:
    is_index = "<sitemapindex" in xml[:2000]
    return is_index, [u.replace("&amp;", "&") for u in LOC.findall(xml)]


def save_raw(url: str, text: str, status: int, tier: int) -> str:
    h = hashlib.sha256(url.encode()).hexdigest()
    path = RAW_DIR / h[:2] / f"{h}.html.gz"
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(text)
    return str(path)


async def worker(router: Router, queue: Queue, con, stop: asyncio.Event,
                 state: dict, limit: int):
    while not stop.is_set():
        rows = queue.claim(limit=1)
        if not rows:
            # Nothing to claim. Finished only if no other worker is mid-fetch
            # (it might still enqueue sitemap children) and nothing is pending.
            stats = queue.stats()
            if (state["busy"] == 0 and stats.get("pending", 0) == 0
                    and stats.get("active", 0) == 0):
                stop.set()
                break
            await asyncio.sleep(0.05)      # yield; don't spin
            continue

        state["busy"] += 1          # no await between claim and this line
        row = rows[0]
        try:
            resp, cfg = await router.fetch(row["url"])
            path = save_raw(row["url"], resp.text, resp.status, resp.tier)
            con.execute(
                "INSERT OR REPLACE INTO raw (hash,url,status,tier,path,fetched) "
                "VALUES (?,?,?,?,?,?)",
                (hashlib.sha256(row["url"].encode()).hexdigest(), row["url"],
                 resp.status, resp.tier, path,
                 datetime.now(timezone.utc).isoformat()))

            if row["kind"] == "api":
                items = api.parse_items(resp.text, cfg.api)
                counts = {}
                for it in items:
                    url, fields = api.item_to_product(it, cfg.api)
                    r = db.save_product(con, cfg, url, fields)
                    counts[r] = counts.get(r, 0) + 1
                con.commit()
                print(f"  [api] {len(items)} items {counts} from {row['url']}")
                queue.done(row["id"], resp.tier)
                continue

            if row["kind"] == "sitemap":
                is_index, urls = parse_sitemap(resp.text)
                if is_index:
                    urls = [u for u in urls if not SKIP_SITEMAPS.search(u)]
                elif limit:
                    urls = urls[:limit]
                for u in urls:
                    queue.add(u, row["domain"],
                              kind="sitemap" if is_index else "page")
                con.commit()
                print(f"  [sitemap] {len(urls)} "
                      f"{'children' if is_index else 'pages'} from {row['url']}")
                queue.done(row["id"], resp.tier)
                continue

            fields, method = extract.extract(resp.text, cfg, row["url"])
            if fields:
                result = db.save_product(con, cfg, row["url"], fields)
            else:
                result = "skipped"
            con.commit()
            print(f"  [{method}] {result:<8} {row['url'][:70]}")
            queue.done(row["id"], resp.tier)
        except Exception as e:
            queue.fail(row["id"], str(e))
            print(f"  [fail] {row['url'][:70]} {e}", file=sys.stderr)
        finally:
            state["busy"] -= 1


async def run(workers: int, limit: int):
    router = Router()
    queue = Queue()
    con = db.connect()

    # Seed: API endpoint, else sitemaps, else the homepage as a last resort.
    for domain, cfg in router.sites.items():
        if cfg.api:
            print(f"seed api {cfg.api['url']}")
            queue.add(cfg.api["url"], domain, kind="api")
        if cfg.sitemaps:
            for sm in cfg.sitemaps[:2]:
                print(f"seed {sm}")
                queue.add(sm, domain, kind="sitemap")
        elif not cfg.api:
            print(f"seed {cfg.base_host}/ (no sitemap)")
            queue.add(f"https://{cfg.base_host}/", domain, kind="page")

    stop = asyncio.Event()
    state = {"busy": 0}
    tasks = [asyncio.create_task(worker(router, queue, con, stop, state, limit))
             for _ in range(workers)]
    print(f"{workers} workers started. queue: {queue.stats()}")
    try:
        await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            t.cancel()
        con.commit()

    print(f"\ndone. queue: {queue.stats()}")
    for r in con.execute("SELECT domain, COUNT(*) AS n FROM products "
                         "GROUP BY domain"):
        print(f"  {r['domain']}: {r['n']} products")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-w", "--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=20,
                    help="max page URLs taken from each flat sitemap "
                         "(0 = no limit)")
    args = ap.parse_args()
    try:
        asyncio.run(run(args.workers, args.limit))
    except KeyboardInterrupt:
        print("\ninterrupted")