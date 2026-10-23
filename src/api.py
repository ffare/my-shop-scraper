"""Extraction for sites whose HTML is a JS shell but that expose a JSON API.

Configured per site in sites.yaml under `api:` (SiteConfig.api). The output
has the same shape the HTML extractors produce, so db.save_product() handles
it unchanged.
"""
import json
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

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


def _fs_value(v):
    """Decode one Firestore REST typed value ({"stringValue": "x"}, ...)."""
    if not isinstance(v, dict) or not v:
        return v
    for key in ("stringValue", "integerValue", "doubleValue", "booleanValue",
                "timestampValue", "referenceValue"):
        if key in v:
            x = v[key]
            return int(x) if key == "integerValue" else x
    if "nullValue" in v:
        return None
    if "arrayValue" in v:
        return [_fs_value(x) for x in v["arrayValue"].get("values", [])]
    if "mapValue" in v:
        return {k: _fs_value(x)
                for k, x in v["mapValue"].get("fields", {}).items()}
    return v


def firestore_doc(doc: dict) -> dict:
    """Firestore REST document -> plain dict, plus its id as `_docid`."""
    out = {k: _fs_value(v) for k, v in (doc.get("fields") or {}).items()}
    out["_docid"] = str(doc.get("name", "")).rsplit("/", 1)[-1]
    return out


def _with_param(url: str, key: str, value) -> str:
    p = urlparse(url)
    query = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k != key]
    query.append((key, str(value)))
    return urlunparse(p._replace(query=urlencode(query)))


def _int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str) and v.strip().isdigit():
        return int(v)
    return None


def _first_int(data: dict, keys):
    for k in keys:
        n = _int(data.get(k))
        if n is not None:
            return n
    return None


def next_page(text: str, url: str, api: dict) -> str | None:
    """URL of the next page of a paginated API, or None.

    Firestore: follows nextPageToken. Page-numbered APIs: when the response
    carries a current page and a total page count (page/pages,
    current_page/last_page, ...), asks for page+1 until the last page. If a
    server ignores the page parameter the URL repeats, and the queue's
    uniqueness check ends the loop.
    """
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if api.get("format") == "firestore":
        token = data.get("nextPageToken")
        return _with_param(url, "pageToken", token) if token else None

    page = _first_int(data, ("page", "current_page", "currentPage"))
    pages = _first_int(data, ("pages", "last_page", "lastPage",
                              "total_pages", "totalPages"))
    if page is not None and pages is not None and page < pages:
        return _with_param(url, "page", page + 1)
    return None


def parse_items(text: str, api: dict) -> list:
    data = json.loads(text)
    if api.get("format") == "firestore":
        return [firestore_doc(d) for d in data.get("documents", [])]
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