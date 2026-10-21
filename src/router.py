"""Tier router. Reads sites.yaml, enforces politeness, escalates on block."""
import asyncio
import time
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from src import fetch_t1
from src.config import SiteConfig, load_sites




class RateLimiter:
    """Per-domain spacing + concurrency cap. Politeness beats throughput."""

    def __init__(self):
        self._next: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}

    def _sem(self, domain: str, concurrency: int) -> asyncio.Semaphore:
        if domain not in self._sems:
            self._sems[domain] = asyncio.Semaphore(concurrency)
        return self._sems[domain]

    @asynccontextmanager                   
    async def slot(self, cfg: SiteConfig):
        async with self._sem(cfg.domain, cfg.concurrency):
            lock = self._locks.setdefault(cfg.domain, asyncio.Lock())
            async with lock:
                wait = self._next.get(cfg.domain, 0) - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
                self._next[cfg.domain] = time.monotonic() + cfg.delay_s
            yield

class Router:
    def __init__(self, sites_path: str = "config/sites.yaml"):
        self.sites = load_sites(sites_path)
        self.limiter = RateLimiter()

    def cfg_for(self, url: str) -> SiteConfig | None:
        host = urlparse(url).netloc.lower()
        for domain, cfg in self.sites.items():
            if host == domain or host == cfg.base_host:
                return cfg
        # allow subdomain match (media.x.tn -> x.tn)
        for domain, cfg in self.sites.items():
            if host.endswith("." + domain):
                return cfg
        return None

    def _rewrite_host(self, url: str, cfg: SiteConfig) -> str:
        """Swap apex for the working host the checker discovered."""
        if cfg.host and cfg.host != cfg.domain:
            p = urlparse(url)
            if p.netloc.lower() == cfg.domain:
                return p._replace(netloc=cfg.host).geturl()
        return url

    async def fetch(self, url: str):
        """Fetch with escalation. Returns (Response, SiteConfig)."""
        cfg = self.cfg_for(url)
        if cfg is None:
            raise KeyError(f"no site config for {url} - add it to sites.txt")
        url = self._rewrite_host(url, cfg)

        last = None
        for tier in range(cfg.tier, 4):
            async with self.limiter.slot(cfg):
                try:
                    if tier == 1:
                        return await fetch_t1.fetch(url), cfg
                    if tier == 2:
                        from src import fetch_t2
                        return await fetch_t2.fetch(url), cfg
                    if tier == 3:
                        from src import fetch_t3
                        return await fetch_t3.fetch(url), cfg
                except fetch_t1.Blocked as e:
                    last = e
                except Exception as e:
                    last = e
        raise RuntimeError(f"all tiers failed for {url}: {last}")