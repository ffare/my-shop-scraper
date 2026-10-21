"""Extraction for sites whose HTML is a JS shell but that expose a JSON API.

Configured per site in sites.yaml under `api:` (SiteConfig.api). The output
has the same shape the HTML extractors produce, so db.save_product() handles
it unchanged.
"""
import json
from urllib.parse import urljoin

DESC_KEYS = ("details", "en", "fr", "ar")


def _get(obj, path):
    """Dotted-path lookup: 'a.b.0.c'. Returns None when any step is missing."""
    for part in str(path).split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


def _description(val):
    """Some APIs store descriptions as a JSON string like {"en":"","details":"..."}."""
    if isinstance(val, str) and val.lstrip().startswith("{"):
        try:
            val = json.loads(val)
        except json.JSONDecodeError:
            return val
    if isinstance(val, dict):
        for k in DESC_KEYS:
            if val.get(k):
                return str(val[k]).strip()
        return None
    return val


def parse_items(text: str, api: dict) -> list:
    data = json.loads(text)
    path = api.get("items", "")
    items = _get(data, path) if path else data
    if not isinstance(items, list):
        raise ValueError(f"expected a list at {path or 'top level'}, "
                         f"got {type(items).__name__}")
    return items


def item_to_product(item: dict, api: dict) -> tuple[str, dict]:
    """Returns (source_url, fields) in the shape db.save_product expects."""
    fields = {}
    for target, src in (api.get("fields") or {}).items():
        val = _get(item, src)
        if isinstance(val, list):
            val = val[0] if val else None          # e.g. first image
        fields[target] = val

    fields["description"] = _description(fields.get("description"))
    if fields.get("image"):
        fields["image"] = urljoin(api["url"], str(fields["image"]))
    if not fields.get("currency"):
        fields["currency"] = api.get("currency")

    # stock flags / quantities -> InStock / OutOfStock
    av = fields.get("availability")
    if isinstance(av, str) and av.strip().isdigit():
        av = int(av)
    if isinstance(av, (bool, int, float)):
        fields["availability"] = "InStock" if av else "OutOfStock"

    # Unique key per product: a mapped URL field, else a product_url template.
    url = None
    if fields.get("url"):
        url = urljoin(api["url"], str(fields["url"]))
    tmpl = api.get("product_url")
    if not url and tmpl:
        flat = {k: v for k, v in item.items() if isinstance(v, (str, int))}
        try:
            url = tmpl.format(**flat)
        except (KeyError, IndexError):
            url = None
    if not url:
        url = (f"{api['url']}#"
               f"{item.get('id') or item.get('slug') or fields.get('sku')}")
    return url, fields