"""SQLite schema + product persistence. Everything is idempotent."""
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

CATALOG = "data/catalog.db"

# Prices are stored as integers in minor units. TND has 3 decimals
# (1 dinar = 1000 millimes), so prices like 269.500 stay exact. The column
# is still called price_cents; read it as "minor units of that currency".
MINOR_UNITS = {"TND": 1000}
DEFAULT_MINOR = 100

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS products (
  id            INTEGER PRIMARY KEY,
  domain        TEXT NOT NULL,
  source_url    TEXT UNIQUE NOT NULL,
  sku           TEXT,
  title         TEXT,
  brand         TEXT,
  price_cents   INTEGER,
  currency      TEXT,
  availability  TEXT,
  category_path TEXT,
  description   TEXT,
  content_hash  TEXT,
  first_seen    TEXT NOT NULL,
  last_seen     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_products_domain ON products(domain);

CREATE TABLE IF NOT EXISTS price_history (
  product_id  INTEGER NOT NULL,
  price_cents INTEGER,
  ts          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS images (
  id         INTEGER PRIMARY KEY,
  product_id INTEGER,
  url        TEXT UNIQUE NOT NULL,
  sha256     TEXT,
  phash      TEXT,
  path       TEXT,
  width      INTEGER,
  height     INTEGER,
  status     TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS raw (
  hash    TEXT PRIMARY KEY,
  url     TEXT NOT NULL,
  status  INTEGER,
  tier    INTEGER,
  path    TEXT NOT NULL,
  fetched TEXT NOT NULL
);
"""

FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS products_fts
  USING fts5(title, brand, description, content='products', content_rowid='id');
"""


def connect(path: str = CATALOG) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    con.executescript(FTS)
    return con


# ------------------------------------------------------------- normalization

def parse_price(raw) -> float | None:
    """'359', '19.9', '1 299,000', '1.299,00', '269,000 DT' -> float.

    A lone comma is treated as the decimal separator (Tunisian convention).
    A lone dot is a decimal unless it forms thousands groups ('1.299.000').
    """
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    s = re.sub(r"[^\d.,]", "", str(raw))
    if not re.search(r"\d", s):
        return None
    if "," in s and "." in s:
        if s.rfind(",") > s.rfind("."):          # 1.299,00
            s = s.replace(".", "").replace(",", ".")
        else:                                     # 1,299.00
            s = s.replace(",", "")
    elif s.count(",") > 1:                        # 1,299,000
        s = s.replace(",", "")
    elif "," in s:                                # 269,000 -> 269.000
        s = s.replace(",", ".")
    elif re.fullmatch(r"\d{1,3}(\.\d{3}){2,}", s):  # 1.299.000
        s = s.replace(".", "")
    try:
        return float(s)
    except ValueError:
        return None


def normalize_availability(raw) -> str | None:
    """schema.org URLs and French/English text -> a small fixed vocabulary."""
    if not raw:
        return None
    s = str(raw).lower()
    for a, b in (("é", "e"), ("è", "e"), ("ê", "e")):
        s = s.replace(a, b)
    s = re.sub(r"[^a-z]", "", s)
    if any(k in s for k in ("outofstock", "soldout", "rupture", "epuise",
                            "indisponible", "unavailable")):
        return "OutOfStock"
    if any(k in s for k in ("preorder", "precommande")):
        return "PreOrder"
    if "backorder" in s:
        return "BackOrder"
    if any(k in s for k in ("instock", "enstock", "disponible", "available")):
        return "InStock"
    return str(raw).strip()[:50]


def _first(v):
    if isinstance(v, list):
        return _first(v[0]) if v else None
    return v


def _s(v):
    if v is None:
        return None
    v = str(v).strip()
    return v or None


def normalize_fields(f: dict) -> dict:
    """Flatten extractor output (meta/microdata/css or a JSON-LD Product)."""
    brand = _first(f.get("brand"))
    if isinstance(brand, dict):
        brand = brand.get("name")

    price, currency, avail = f.get("price"), f.get("currency"), f.get("availability")
    offers = _first(f.get("offers"))
    if isinstance(offers, dict):
        price = price or offers.get("price") or offers.get("lowPrice")
        currency = currency or offers.get("priceCurrency")
        avail = avail or offers.get("availability")

    image = _first(f.get("image"))
    if isinstance(image, dict):
        image = image.get("url")

    return {
        "title": _s(_first(f.get("title") or f.get("name"))),
        "sku": _s(_first(f.get("sku"))),
        "brand": _s(brand),
        "price": parse_price(_first(price)),
        "currency": _s(_first(currency)),
        "availability": normalize_availability(_first(avail)),
        "image": _s(image),
        "description": _s(_first(f.get("description"))),
    }


# --------------------------------------------------------------- persistence

def _fts_insert(con, pid, n):
    con.execute("INSERT INTO products_fts(rowid, title, brand, description) "
                "VALUES (?,?,?,?)", (pid, n["title"], n["brand"], n["description"]))


def _fts_delete(con, old):
    # external-content FTS5: must delete using the OLD indexed values
    con.execute("INSERT INTO products_fts(products_fts, rowid, title, brand, "
                "description) VALUES ('delete',?,?,?,?)",
                (old["id"], old["title"], old["brand"], old["description"]))


def save_product(con, cfg, url: str, fields: dict) -> str:
    """Upsert one product. Returns 'new', 'updated', 'same' or 'skipped'.

    Pages without a title and a parseable price (categories, brand pages,
    CMS pages) are skipped so they never look like products. The caller
    commits.
    """
    n = normalize_fields(fields)
    if not n["title"] or n["price"] is None:
        return "skipped"

    minor = MINOR_UNITS.get((n["currency"] or "").upper(), DEFAULT_MINOR)
    price_minor = round(n["price"] * minor)
    now = datetime.now(timezone.utc).isoformat()
    chash = hashlib.sha256(json.dumps(
        [n["title"], n["sku"], n["brand"], price_minor, n["currency"],
         n["availability"], n["description"]],
        ensure_ascii=False).encode()).hexdigest()

    old = con.execute("SELECT * FROM products WHERE source_url=?",
                      (url,)).fetchone()
    if old is None:
        cur = con.execute(
            "INSERT INTO products (domain, source_url, sku, title, brand, "
            "price_cents, currency, availability, description, content_hash, "
            "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (cfg.domain, url, n["sku"], n["title"], n["brand"], price_minor,
             n["currency"], n["availability"], n["description"], chash,
             now, now))
        pid = cur.lastrowid
        con.execute("INSERT INTO price_history VALUES (?,?,?)",
                    (pid, price_minor, now))
        _fts_insert(con, pid, n)
        result = "new"
    elif old["content_hash"] == chash:
        pid = old["id"]
        con.execute("UPDATE products SET last_seen=? WHERE id=?", (now, pid))
        result = "same"
    else:
        pid = old["id"]
        _fts_delete(con, old)
        con.execute(
            "UPDATE products SET sku=?, title=?, brand=?, price_cents=?, "
            "currency=?, availability=?, description=?, content_hash=?, "
            "last_seen=? WHERE id=?",
            (n["sku"], n["title"], n["brand"], price_minor, n["currency"],
             n["availability"], n["description"], chash, now, pid))
        if old["price_cents"] != price_minor:
            con.execute("INSERT INTO price_history VALUES (?,?,?)",
                        (pid, price_minor, now))
        _fts_insert(con, pid, n)
        result = "updated"

    if n["image"]:
        con.execute("INSERT OR IGNORE INTO images (product_id, url) VALUES (?,?)",
                    (pid, n["image"]))
    return result