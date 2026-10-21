"""Find a site's JSON product API when its HTML is an empty JS shell.

Candidate endpoints come from two places, and every candidate is validated by
actually fetching it and checking that the JSON looks like a product list:
  1. /api/... strings found inside the page's own JavaScript bundles
  2. common paths (/api/products, /products.json, ...)

Returns a ready-to-use `api:` config block (see src/api.py) plus notes.
Same-origin endpoints only: the crawler's router matches requests to a site
by host, so an API on another host would not resolve to a site config.
"""
import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

from curl_cffi.requests import AsyncSession

from src.api import _get
from src.db import parse_price

COMMON_PATHS = [
    "/api/products", "/api/v1/products", "/api/v2/products", "/api/product",
    "/api/items", "/api/catalog", "/api/store/products", "/api/shop/products",
    "/products.json", "/wp-json/wc/store/v1/products", "/api/articles",
]

SHELL_MARKERS = ('id="root"', "id='root'", 'id="app"', 'id="__next"',
                 'id="__nuxt"', "/_next/", "/assets/index-")

SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
API_STR = re.compile(r'["\'`](/api/[A-Za-z0-9_\-/]+)')
HINT = re.compile(r"product|item|catalog|shop|store|article|listing|"
                  r"collection|goods", re.I)
BAD = re.compile(r"cart|order|checkout|login|auth|user|account|admin|upload|"
                 r"contact|payment|webhook|newsletter|review|wishlist", re.I)

# our field -> JSON keys to try, in priority order (case/underscore-insensitive;
# dotted entries are exact nested paths, e.g. Shopify's variants.0.price)
ALIASES = {
    "title": ["name", "title", "product_name", "label"],
    "price": ["price", "regular_price", "sale_price", "selling_price",
              "unit_price", "variants.0.price", "offers.price",
              "price.amount", "price.value"],
    "sku": ["sku", "code", "reference", "ref", "variants.0.sku", "id", "slug"],
    "description": ["description", "desc", "short_description", "body_html",
                    "details"],
    "image": ["images", "image", "image_url", "thumbnail", "picture", "photo",
              "images.0.src", "images.0.url", "featured_image"],
    "availability": ["in_stock", "available", "is_available", "stock",
                     "quantity", "stock_quantity", "availability",
                     "inventory_quantity"],
    "brand": ["brand", "vendor", "manufacturer"],
    "currency": ["currency", "currency_code", "price_currency"],
    "url": ["url", "link", "permalink", "href"],
}

TLD_CURRENCY = {"tn": "TND", "ma": "MAD", "dz": "DZD", "eg": "EGP",
                "fr": "EUR", "de": "EUR", "it": "EUR", "es": "EUR",
                "uk": "GBP"}

PREFERRED = ("products", "items", "data", "results", "records", "rows", "docs")
PAGING_KEYS = {"next", "nextpage", "totalpages", "pages", "page", "perpage",
               "limit", "total", "count", "hasmore", "cursor", "pagination",
               "links", "meta"}
COMMON_PAGE_SIZES = {10, 12, 15, 20, 24, 25, 30, 40, 48, 50, 60, 100}


def looks_like_shell(html: str) -> bool:
    """A small page with an app-mount marker: content is built by JavaScript."""
    return len(html) < 20_000 and any(m in html for m in SHELL_MARKERS)


async def _fetch(url, timeout=20):
    async with AsyncSession(impersonate="chrome") as s:
        return await s.get(url, timeout=timeout, headers={
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "fr-FR,fr;q=0.9"})


async def _fetch_json(url):
    try:
        r = await _fetch(url)
    except Exception:
        return None
    if r.status_code != 200:
        return None
    text = r.text
    if text.lstrip()[:1] not in ("[", "{"):      # SPAs answer 200 with HTML
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def _find_items(data, prefix="", depth=0):
    """First list of dicts in the JSON -> (dotted path to it, the list)."""
    if isinstance(data, list):
        if data and all(isinstance(x, dict) for x in data[:5]):
            return prefix.rstrip("."), data
        return None, None
    if isinstance(data, dict) and depth < 3:
        for k in sorted(data, key=lambda k: k not in PREFERRED):
            path, items = _find_items(data[k], f"{prefix}{k}.", depth + 1)
            if items:
                return path, items
    return None, None


def _real_path(item: dict, alias: str):
    """Path in `item` matching `alias`, ignoring case and underscores."""
    head, _, rest = alias.partition(".")
    for k in item:
        if _norm(k) == _norm(head):
            return k + ("." + rest if rest else "")
    return None


def _usable(v, allow_list=False) -> bool:
    if isinstance(v, list):
        return allow_list and bool(v) and isinstance(v[0], (str, int, float))
    if isinstance(v, str):
        return bool(v.strip())
    return isinstance(v, (int, float, bool))


def _map_fields(sample: list):
    mapping = {}
    for target, aliases in ALIASES.items():
        for alias in aliases:
            path = _real_path(sample[0], alias)
            if not path:
                continue
            vals = [_get(it, path) for it in sample]
            ok = [v for v in vals if _usable(v, allow_list=(target == "image"))]
            if len(ok) < 0.8 * len(sample):
                continue
            if target == "price":
                good = [v for v in ok if (parse_price(v) or 0) > 0]
                if len(good) < 0.8 * len(sample):
                    continue
            mapping[target] = path
            break
    return mapping if "title" in mapping and "price" in mapping else None


def _identity_ok(items: list, mapping: dict) -> bool:
    """Every product needs a unique key, or they overwrite each other."""
    for path in (mapping.get("url"), "id", "slug", mapping.get("sku")):
        if not path:
            continue
        vals = [_get(it, path) for it in items]
        if all(v is not None for v in vals) and len(set(map(str, vals))) == len(vals):
            return True
    return False


async def _paging_notes(url, data, items) -> list:
    """Report whether the API paginates, by actually asking for page 2."""
    notes = []
    if isinstance(data, dict):
        hits = sorted(k for k in data if _norm(k) in PAGING_KEYS)
        if hits:
            notes.append(f"pagination keys present ({', '.join(hits)}) - "
                         "the crawler reads only this first page")

    def ident(it):
        for k in ("id", "slug", "sku"):
            if k in it:
                return str(it[k])
        return json.dumps(it, sort_keys=True)[:200]

    first = {ident(it) for it in items}
    _, items2 = _find_items(await _fetch_json(f"{url}?page=2"))
    if items2 and any(ident(it) not in first for it in items2):
        notes.append("API IS PAGINATED: ?page=2 returns different items - "
                     "the crawler reads only page 1")
    else:
        notes.append("?page=2 returned no new items (offset/cursor paging "
                     "was not tested)")
    return notes


async def _endpoints_from_js(host: str, html: str) -> list:
    base = f"https://{host}/"
    found = []
    scripts = [urljoin(base, s) for s in SCRIPT_SRC.findall(html or "")]
    scripts = [u for u in scripts
               if urlparse(u).netloc.lower() == host.lower() and ".js" in u]
    for u in scripts[:4]:
        try:
            r = await _fetch(u, timeout=30)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        for m in API_STR.finditer(r.text[:3_000_000]):
            path = m.group(1).rstrip("/")
            if (HINT.search(path) and not BAD.search(path)
                    and path not in found):
                found.append(path)
        await asyncio.sleep(0.2)
    return found[:10]


async def discover_api(host: str, html: str, default_currency: str | None = None):
    """Returns (api_block or None, notes)."""
    notes = []
    from_js = await _endpoints_from_js(host, html)
    candidates = from_js + [p for p in COMMON_PATHS if p not in from_js]

    tried = 0
    for path in candidates[:20]:
        tried += 1
        data = await _fetch_json(f"https://{host}{path}")
        await asyncio.sleep(0.3)
        if data is None:
            continue
        items_path, items = _find_items(data)
        if not items:
            continue
        mapping = _map_fields(items[:25])
        if not mapping or not _identity_ok(items, mapping):
            continue

        block = {"url": f"https://{host}{path}", "items": items_path or ""}
        if "currency" not in mapping:
            cur = (TLD_CURRENCY.get(host.rsplit(".", 1)[-1])
                   or default_currency)
            if cur:
                block["currency"] = cur
            else:
                notes.append("API has no currency field and the domain gives "
                             "no hint - rerun with --currency XXX or set "
                             "api.currency")
        block["fields"] = mapping

        notes.append(f"JSON API found: {path} ({len(items)} items, list at "
                     f"{items_path or 'top level'})")
        notes.append("api fields: " + ", ".join(
            f"{k}<-{v}" for k, v in mapping.items()))
        if "url" not in mapping:
            notes.append("no product page URL in the API; products are keyed "
                         "by API URL + id")
        notes.extend(await _paging_notes(block["url"], data, items))
        return block, notes

    notes.append(f"no JSON API found ({tried} candidates tried)")
    if from_js:
        notes.append("endpoints seen in the site's JS: " + ", ".join(from_js))
    return None, notes