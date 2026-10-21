"""Typed loader for config/sites.yaml. Written by checker.py, read by router."""
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_PATH = "config/sites.yaml"


@dataclass
class SiteConfig:
    domain: str
    tier: int = 1
    concurrency: int = 2
    delay_s: float = 1.0
    extract: str = "css"
    verified: bool = True
    host: str = None
    platform: str = None
    platform_api: str = None
    status: str = None
    sitemaps: list = field(default_factory=list)
    selectors: dict = field(default_factory=dict)

    @property
    def base_host(self) -> str:
        """Host to actually fetch from (checker may have found www differs)."""
        return self.host or self.domain

    @property
    def needs_review(self) -> bool:
        return not self.verified


def load_sites(path: str = DEFAULT_PATH) -> dict[str, SiteConfig]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found - run the checker first")
    data = yaml.safe_load(p.read_text()) or {}
    sites = {}
    for domain, cfg in data.items():
        cfg = cfg or {}
        known = set(SiteConfig.__dataclass_fields__) - {"domain"}
        clean = {k: v for k, v in cfg.items() if k in known}
        sites[domain] = SiteConfig(domain=domain, **clean)
    return sites