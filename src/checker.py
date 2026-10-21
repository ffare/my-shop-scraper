# src/checker.py
import argparse
import asyncio
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml
from curl_cffi.requests import AsyncSession

# Shared with the crawler so the checker and the crawl use the same logic.
# Run as a module from the project root: python -m src.checker
from types import SimpleNamespace

from src.extract import PLATFORM_SELECTORS, extract, from_css

# NOTE: no custom User-Agent anywhere. impersonate="chrome" sends a UA that
# matches its TLS fingerprint; overriding it creates a detectable mismatch.
# Every probe uses curl_cffi so the checker sees what the crawler sees.

ANTIBOT = {
    "cloudflare":  {"hdr": ["cf-ray", "cf-mitigated"], "srv": ["cloudflare"],
                    "ck": ["__cf_bm", "cf_clearance"],
                    "body": ["just a moment", "cf-chl", "turnstile"]},
    "datadome":    {"hdr": ["x-datadome"], "ck": ["datadome"],
                    "body": ["captcha-delivery.com"]},
    "akamai":      {"srv": ["akamaighost"], "ck": ["ak_bmsc", "_abck"],
                    "hdr": ["x-akamai"]},
    "perimeterx":  {"ck": ["_px", "_pxhd"], "hdr": ["x-px"],
                    "body": ["px-captcha"]},
    "kasada":      {"hdr": ["x-kpsdk-ct", "x-kpsdk-cd"]},
    "imperva":     {"ck": ["incap_ses", "visid_incap"], "hdr": ["x-iinfo"]},
}
HARD_ANTIBOT = {"datadome", "kasada", "perimeterx", "imperva"}

# Signature order matters only for equal-strength matches: first wins.
# header/server/hdrval/cookie hits outrank body-only hits.
PLATFORMS = {
    "shopify":     {"hdr": ["x-shopify-stage", "x-shopid"],
                    "body": ["cdn.shopify.com"],
                    "ep": "/products.json"},
    "woocommerce": {"hdrval": ["woocommerce"],
                    "body": ["wp-content/plugins/woocommerce", "wc-ajax"],
                    "ep": "/wp-json/wc/store/v1/products"},
    "magento":     {"hdr": ["x-magento-vary", "x-magento-tags",
                            "x-magento-cache-debug"],
                    "ck": ["private_content_version", "mage-cache"],
                    "body": ["static/version", "mage/requirejs", "magento_"],
                    "ep": "/graphql", "post": True},
    "prestashop":  {"ck": ["prestashop-"],
                    "hdrval": ["prestashop"],
                    "body": ["modules/ps_", "var prestashop"],
                    "ep": None},
    "bigcommerce": {"hdr": ["x-bc-storefront"],
                    "body": ["bigcommerce"],
                    "ep": "/api/storefront/products"},
    "nextjs":      {"body": ["__next_data__", "/_next/static/"], "ep": None},
}

GRAPHQL_PROBE = {"query": "{ storeConfig { store_name } }"}

# Matches currency before the number ("DT 269") or after it ("269,000 DT").
PRICE_RE = re.compile(
    r"(?:(?:\$|€|£|DT\b|TND\b|MAD\b)\s?\d"
    r"|\d[\d\s.,]*\s?(?:DT|TND|MAD|€|\$|£)(?!\w))",
    re.IGNORECASE)
JSONLD_RE = re.compile(r'"@type"\s*:\s*"product"', re.IGNORECASE)

STRONG_HITS = {"header", "server", "hdrval", "cookie"}


@dataclass
class Profile:
    domain: str
    host: str = None
    reachable: bool = True
    status: str = "ok"
    tier: int = 1
    platform: str = None
    server: str = None
    antibot: list = field(default_factory=list)
    challenge: bool = False
    needs_js: bool = False
    needs_impersonation: bool = False
    jsonld: bool = False
    sitemaps: list = field(default_factory=list)
    sitemap_urls: int = 0
    sitemap_is_index: bool = False
    selectors: dict = field(default_factory=dict)
    extraction_ok: bool = True
    crawl_delay: float = None
    concurrency: int = 2
    notes: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


# ---------------------------------------------------------------- HTTP helpers

async def cffi_get(url, timeout=25):
    async with AsyncSession(impersonate="chrome") as s:
        return await s.get(url, timeout=timeout,
                           headers={"Accept-Language": "fr-FR,fr;q=0.9"})


async def cffi_post(url, json, timeout=15):
    async with AsyncSession(impersonate="chrome") as s:
        return await s.post(url, json=json, timeout=timeout,
                            headers={"Accept-Language": "fr-FR,fr;q=0.9"})


# --------------------------------------------------------------------- parsing

def _host_variants(domain):
    """Try the given host first, then the other www/apex form."""
    if domain.startswith("www."):
        return [domain, domain[4:]]
    return [domain, "www." + domain]


def load_sites(path):
    """Parse sites.txt -> [(host, sample_product_or_None)]."""
    sites, seen = [], set()
    with open(path) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            entry = parts[0]
            if "://" not in entry:
                entry = "https://" + entry
            host = urlparse(entry).netloc.lower()
            if not host:
                print(f"  ! line {lineno}: unparseable, skipping")
                continue
            if host in seen:
                print(f"  ! line {lineno}: duplicate {host}, skipping")
                continue
            seen.add(host)

            sample = parts[1] if len(parts) > 1 else None
            if sample and not sample.startswith("http"):
                sample = f"https://{host}/{sample.lstrip('/')}"
            sites.append((host, sample))
    return sites


def _match(sig, headers, cookies, body):
    hits = []
    hdrs = {k.lower() for k in headers}
    hdrvals = " ".join(str(v) for v in headers.values()).lower()
    srv = (headers.get("server") or "").lower()

    if any(h in hdrs for h in sig.get("hdr", [])):
        hits.append("header")
    if any(s in srv for s in sig.get("srv", [])):
        hits.append("server")
    if any(v in hdrvals for v in sig.get("hdrval", [])):
        hits.append("hdrval")
    # cookies is a set of names -> substring match (e.g. "prestashop-" prefix)
    if any(any(c.lower() in ck for ck in cookies) for c in sig.get("ck", [])):
        hits.append("cookie")
    if any(b in body for b in sig.get("body", [])):
        hits.append("body")
    return hits


# ---------------------------------------------------------------------- probes

async def probe_headers(domain):
    """Try apex and www; return the first host that answers."""
    errors = []
    for host in _host_variants(domain):
        try:
            r = await cffi_get(f"https://{host}/", timeout=20)
            cookies = {name.lower() for name in r.cookies.keys()}
            return r, cookies, r.text[:200_000].lower(), host
        except Exception as e:
            msg = str(e)
            kind = ("cert mismatch"
                    if "certificate" in msg.lower() and "verify" in msg.lower()
                    else f"{type(e).__name__}: {msg[:120]}")
            errors.append(f"{host}: {kind}")
    raise ConnectionError("; ".join(errors))


async def probe_platform(host, sig):
    """Only called for platforms that declare an endpoint."""
    ep = sig.get("ep")
    if not ep:
        return False
    try:
        url = f"https://{host}{ep}"
        if sig.get("post"):
            r = await cffi_post(url, GRAPHQL_PROBE)
        else:
            r = await cffi_get(url, timeout=15)
        return r.status_code == 200 and len(r.content) > 100
    except Exception:
        return False


async def probe_impersonation(host):
    """Informational only: does the homepage succeed under impersonation?"""
    try:
        r = await cffi_get(f"https://{host}/")
        return r.status_code
    except Exception:
        return None


async def probe_product_page(url):
    """Returns (jsonld_present, price_in_html, status_code, html)."""
    try:
        r = await cffi_get(url)
    except Exception:
        return False, False, None, ""
    html = r.text
    return (bool(JSONLD_RE.search(html)),
            bool(PRICE_RE.search(html)),
            r.status_code,
            html)


def report_extraction(p, html, url):
    """Run the real extraction ladder on the sample page and report the result.

    Flags the site for review when the essentials (a name and a price) are
    missing, so a site that needs selectors is caught at check time.
    """
    cfg = SimpleNamespace(platform=p.platform, selectors=p.selectors)
    fields, method = extract(html, cfg, url)
    if not fields:
        p.extraction_ok = False
        p.notes.append("extraction: NOTHING found - site needs selectors")
        return

    have = set(fields)
    if "offers" in have:                    # JSON-LD keeps these nested
        have |= {"price", "availability"}
    if "name" in have:
        have.add("title")
    p.notes.append(f"extraction [{method}]: {', '.join(sorted(fields))}")

    missing_essential = [f for f in ("title", "price") if f not in have]
    if missing_essential:
        p.extraction_ok = False
        p.notes.append("extraction: MISSING essential "
                       f"{', '.join(missing_essential)} - add selectors")
    for f in ("sku", "availability"):
        if f not in have:
            p.notes.append(f"extraction: no {f} found (optional)")


def verify_selectors(p, html):
    """Try the platform's default selectors on the sample page.

    Keeps only the ones that return a value, and reports the rest, so a
    broken selector shows up at check time instead of as silent meta
    fallbacks during a crawl.
    """
    defaults = PLATFORM_SELECTORS.get(p.platform)
    if not defaults:
        p.notes.append(f"no default selectors for platform {p.platform!r}"
                       " (jsonld/meta only unless you add some)")
        return
    found = from_css(html, defaults) or {}
    p.selectors = {f: sel for f, sel in defaults.items() if f in found}
    missing = [f for f in defaults if f not in found]
    p.notes.append(f"selectors verified: {', '.join(p.selectors) or 'none'}")
    for f in missing:
        p.notes.append(f"selector FAILED on sample page: {f} = {defaults[f]!r}")
    if found:
        sample = ", ".join(f"{k}={str(v)[:30]!r}" for k, v in found.items())
        p.notes.append(f"sample values: {sample}")


async def probe_robots(host):
    try:
        r = await cffi_get(f"https://{host}/robots.txt", timeout=15)
    except Exception:
        return None, []
    if r.status_code != 200:
        return None, []
    sitemaps = re.findall(r"(?i)sitemap:\s*(\S+)", r.text)
    delay = re.search(r"(?i)crawl-delay:\s*([\d.]+)", r.text)
    return (float(delay.group(1)) if delay else None), sitemaps


async def probe_sitemap(url):
    """Returns (entry_count, is_index)."""
    try:
        r = await cffi_get(url, timeout=20)
    except Exception:
        return 0, False
    if r.status_code != 200:
        return 0, False
    return (len(re.findall(r"<loc>", r.text)),
            "<sitemapindex" in r.text[:2000])


async def detect_platform(p, headers, cookies, body):
    """Record platform from the strongest signature match.

    Detection does NOT require a working API endpoint - PrestaShop and
    Next.js have no public JSON API at all.
    """
    candidates = []
    for name, sig in PLATFORMS.items():
        hits = _match(sig, headers, cookies, body)
        if hits:
            strong = any(h in STRONG_HITS for h in hits)
            candidates.append((0 if strong else 1, name, sig, hits))
    if not candidates:
        return
    candidates.sort(key=lambda c: c[0])
    _, name, sig, hits = candidates[0]
    p.platform = name
    via = ",".join(hits)
    if sig.get("ep") and await probe_platform(p.host, sig):
        p.notes.append(f"native API confirmed: {sig['ep']} (via {via})")
    elif sig.get("ep"):
        p.notes.append(f"detected via {via}; {sig['ep']} did NOT respond")
    else:
        p.notes.append(f"detected via {via} (no public API)")


# ----------------------------------------------------------------------- check

async def check(domain, sample_product=None):
    p = Profile(domain=domain)
    try:
        r, cookies, body, p.host = await probe_headers(domain)
    except ConnectionError as e:
        p.reachable = False
        p.status = "unreachable"
        p.tier = 1                      # NOT 3 - we don't know yet
        p.notes.append(f"unreachable: {e}")
        p.notes.append("tier is a GUESS - verify by hand")
        return p

    if p.host != domain:
        p.notes.append(f"canonical host is {p.host} (apex/www differs)")
    p.server = r.headers.get("server", "")
    p.evidence = {
        "server": p.server,
        "cookies": sorted(cookies),
        "xheaders": sorted(k for k in r.headers if k.lower().startswith("x-")),
    }

    headers = dict(r.headers)

    # Anti-bot fingerprinting
    for name, sig in ANTIBOT.items():
        hits = _match(sig, headers, cookies, body)
        if hits:
            p.antibot.append(name)
            # Strings like "turnstile" / "cf-chl" also appear in the scripts
            # of normal Cloudflare pages, so only trust body hits on pages
            # that look like challenges (non-200 or tiny).
            if "body" in hits and (r.status_code != 200 or len(body) < 20_000):
                p.challenge = True
    if r.status_code in (403, 429, 503) and p.antibot:
        p.challenge = True

    # Platform detection (uses the host that actually answered)
    await detect_platform(p, headers, cookies, body)

    # Impersonation: informational only. Tier 1 already impersonates, so this
    # must not promote a site to a heavier tier.
    if r.status_code in (403, 429) or p.challenge:
        code = await probe_impersonation(p.host)
        p.needs_impersonation = code == 200
        p.notes.append(f"challenge/403 on homepage; retry status={code}")

    # robots + sitemaps
    p.crawl_delay, sitemaps = await probe_robots(p.host)
    p.sitemaps = sitemaps[:5]
    if sitemaps:
        p.sitemap_urls, p.sitemap_is_index = await probe_sitemap(sitemaps[0])
        if p.sitemap_is_index:
            p.notes.append(f"sitemap is an index with {p.sitemap_urls} children")

    # JS dependency + JSON-LD
    if sample_product:
        p.jsonld, rendered, st, html = await probe_product_page(sample_product)
        p.needs_js = not rendered and not p.jsonld
        p.notes.append(f"product probe: status={st} jsonld={p.jsonld} "
                       f"price_in_html={rendered}")
        if html and st == 200:
            verify_selectors(p, html)
            report_extraction(p, html, sample_product)
        else:
            p.notes.append("selector check skipped (no usable sample page)")
    else:
        p.notes.append("no sample product URL - JS and selector probes skipped")

    # --- Score ---
    if any(a in HARD_ANTIBOT for a in p.antibot):
        p.tier = 3
    elif "cloudflare" in p.antibot and p.challenge:
        p.tier = 3
    elif p.needs_js:
        p.tier = 2
    else:
        p.tier = 1

    # Politeness
    if p.crawl_delay:
        p.concurrency = max(1, int(1 / p.crawl_delay))
    elif p.tier == 3:
        p.concurrency = 1
    elif p.tier == 2:
        p.concurrency = 2
    else:
        p.concurrency = 4
    if p.sitemap_urls > 100_000 and not p.sitemap_is_index:
        p.notes.append("large catalog - shard by sitemap")
    return p


def to_config(p):
    cfg = {"tier": p.tier,
           "concurrency": p.concurrency,
           "delay_s": p.crawl_delay or (2.0 if p.tier == 3 else 1.0),
           "extract": "jsonld" if p.jsonld else "css",
           "verified": p.reachable and p.extraction_ok}
    if p.host and p.host != p.domain:
        cfg["host"] = p.host
    if not p.reachable:
        cfg["status"] = p.status
    if p.platform:
        cfg["platform"] = p.platform
        if any("native API confirmed" in n for n in p.notes):
            cfg["platform_api"] = p.platform
    if p.tier == 3:
        cfg["browser"] = "camoufox"
    if p.sitemaps:
        cfg["sitemaps"] = p.sitemaps
    if p.selectors:
        cfg["selectors"] = p.selectors
    return cfg


# ------------------------------------------------------------------------ main

async def main(sites, out, workers, verbose):
    sem = asyncio.Semaphore(workers)
    results = [None] * len(sites)

    async def run(i, domain, sample):
        async with sem:
            try:
                results[i] = await check(domain, sample)
            except Exception as e:
                p = Profile(domain=domain)
                p.reachable = False
                p.status = "check_failed"
                p.tier = 1
                p.notes = [f"check failed: {type(e).__name__}: {e}"]
                results[i] = p

    await asyncio.gather(*(run(i, d, s) for i, (d, s) in enumerate(sites)))

    for p in results:
        flag = " ".join(p.antibot) or "-"
        print(f"[T{p.tier}] {p.domain:<32} {flag:<22} {p.platform or ''}")
        for n in p.notes:
            print(f"        · {n}")
        if verbose and p.evidence:
            ev = p.evidence
            print(f"        evidence: server={ev.get('server')!r}")
            if ev.get("cookies"):
                print(f"        cookies: {', '.join(ev['cookies'][:15])}")
            if ev.get("xheaders"):
                print(f"        x-headers: {', '.join(ev['xheaders'][:15])}")

    # Merge instead of overwrite: keep sites not in this run, and keep any
    # hand-written selectors for sites that are re-checked.
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if Path(out).exists():
        existing = yaml.safe_load(Path(out).read_text()) or {}

    fresh = {}
    for p in results:
        cfg = to_config(p)
        old = existing.get(p.domain) or {}
        if old.get("selectors"):
            # hand-written (or previously saved) selectors win on conflict
            cfg["selectors"] = {**cfg.get("selectors", {}), **old["selectors"]}
        fresh[p.domain] = cfg

    with open(out, "w") as f:
        yaml.safe_dump({**existing, **fresh}, f, sort_keys=False)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Tier-classify e-commerce sites.")
    ap.add_argument("file", nargs="?", default="sites.txt",
                    help="file with one domain per line (default: sites.txt)")
    ap.add_argument("-o", "--out", default="config/sites.yaml",
                    help="output config path")
    ap.add_argument("-w", "--workers", type=int, default=4,
                    help="sites checked in parallel (default: 4)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print raw headers/cookies as detection evidence")
    args = ap.parse_args()

    sites = load_sites(args.file)
    if not sites:
        sys.exit(f"no sites found in {args.file}")
    print(f"checking {len(sites)} sites, {args.workers} at a time\n")
    asyncio.run(main(sites, args.out, args.workers, args.verbose))