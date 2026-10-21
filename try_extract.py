import gzip, hashlib, sys
from src import extract
from src.router import Router

url = sys.argv[1]
cfg = Router().cfg_for(url)
h = hashlib.sha256(url.encode()).hexdigest()
html = gzip.open(f"data/raw/{h[:2]}/{h}.html.gz", "rt").read()
fields, method = extract.extract(html, cfg, url)
print(method)
for k, v in (fields or {}).items():
    print(f"  {k}: {str(v)[:100]}")