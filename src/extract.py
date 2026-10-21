"""Extraction ladder, merged per field (earlier methods win):
JSON-LD -> embedded state -> microdata -> CSS selectors -> meta tags.
"""
import json
import re
from pathlib import Path

import yaml

try:
    from selectolax.parser import HTMLParser          # selectolax < 1.0
except ImportError:
    from selectolax.lexbor import LexborHTMLParser as HTMLParser  # >= 1.0

SELECTORS_PATH = "config/selectors.yaml"

JSONLD_BLOCK = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.DOTALL | re.IGNORECASE)
NEXT_DATA = re.compile(
    r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.DOTALL)

META_MAP = {
    "og:title": "title",
    "og:description": "description",
    "og:image": "image",
    "og:brand": "brand",
    "product:brand": "brand",
    "product:price:amount": "price",
    "product:price:currency": "currency",
    "product:availability": "availability",
    "og:availability": "availability",
}

# schema.org microdata. Whitelisted on purpose: itemprop="name" also appears
# in breadcrumbs, so grabbing every itemprop would pick the wrong name.
MICRODATA_FIELDS = {
    "sku": "sku",
    "price": "price",
    "pricecurrency": "currency",
    "availability": "availability",
    "brand": "brand",
    "gtin": "gtin",
    "mpn": "mpn",
}


def load_platform_selectors(path: str = SELECTORS_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return (yaml.safe_load(p.read_text()) or {}).get("platforms", {})


PLATFORM_SELECTORS = load_platform_selectors()


def _walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def from_jsonld(html: str) -> dict | None:
    for block in JSONLD_BLOCK.findall(html):
        try:
            data = json.loads(block.strip())
        except json.JSONDecodeError:
            continue
        for node in _walk(data):
            t = node.get("@type")
            if t == "Product" or (isinstance(t, list) and "Product" in t):
                return node
    return None


def from_next_data(html: str) -> dict | None:
    m = NEXT_DATA.search(html)
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    for node in _walk(data):
        if node.get("name") and ("price" in node or "sku" in node):
            return node
    return None


def from_microdata(html: str) -> dict | None:
    tree = HTMLParser(html)
    out = {}
    for node in tree.css("[itemprop]"):
        field = MICRODATA_FIELDS.get(node.attributes.get("itemprop", "").lower())
        if not field or field in out:
            continue
        val = (node.attributes.get("content") or node.attributes.get("href")
               or node.text(strip=True))
        if val and val.strip():          # skips empty JS placeholders
            out[field] = val.strip()
    return out or None


def from_css(html: str, selectors: dict) -> dict | None:
    """Selectors may end in @attr to read an attribute instead of text.
    Uses the first NON-EMPTY match, so empty placeholder elements are skipped.
    A bad selector is skipped rather than raising.
    """
    if not selectors:
        return None
    tree = HTMLParser(html)
    out = {}
    for field, sel in selectors.items():
        attr = None
        if "@" in sel:
            sel, attr = sel.rsplit("@", 1)
        try:
            nodes = tree.css(sel)
        except ValueError:
            continue
        for node in nodes:
            val = node.attributes.get(attr) if attr else node.text(strip=True)
            if val and val.strip():
                out[field] = val.strip()
                break
    return out or None


def from_meta(html: str) -> dict | None:
    tree = HTMLParser(html)
    out = {}
    for node in tree.css("meta"):
        key = (node.attributes.get("property")
               or node.attributes.get("name") or "").lower()
        content = node.attributes.get("content")
        field = META_MAP.get(key)
        if field and content and field not in out:
            out[field] = content
    return out if out.get("title") else None


def extract(html: str, cfg, url: str) -> tuple[dict | None, str]:
    """Returns (fields, methods_used). Earlier methods win per field."""
    # Site-specific selectors override the platform defaults.
    selectors = {**PLATFORM_SELECTORS.get(cfg.platform, {}), **cfg.selectors}

    out, methods = {}, []
    for name, fn in [("jsonld", lambda: from_jsonld(html)),
                     ("next_data", lambda: from_next_data(html)),
                     ("microdata", lambda: from_microdata(html)),
                     ("css", lambda: from_css(html, selectors)),
                     ("meta", lambda: from_meta(html))]:
        if (p := fn()):
            for k, v in p.items():
                out.setdefault(k, v)
            methods.append(name)
    return (out or None), "+".join(methods) or "none"