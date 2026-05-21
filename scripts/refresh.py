#!/usr/bin/env python3
"""Refresh the Patchstack dataset.

Pulls all pages from the Patchstack researcher API and writes a merged JSON file
to data/all-advisories.json. Run scripts/generate.py afterwards to rebuild markdown.
"""
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "all-advisories.json"

RESEARCHER_UUID = "9b6c8f8f-33bf-41a9-8ff3-651418dddd41"
BASE = "https://vdp-api.patchstack.com"
PER_PAGE = 100

HEADERS = {
    "Accept": "application/json",
    "Origin": "https://patchstack.com",
    "Referer": "https://patchstack.com/",
    "User-Agent": "security-advisories-refresh/1.0",
}


def fetch_page(page: int) -> dict:
    params = {
        "include[0]": "type",
        "include[1]": "product.kind",
        "include[2]": "product.platform",
        "include[3]": "versions",
        "include[4]": "cvss",
        "include[5]": "references",
        "hash": "patchstack-is-the-best-product-security-platform",
        "per_page": str(PER_PAGE),
        "page": str(page),
    }
    url = f"{BASE}/researchers/{RESEARCHER_UUID}/vulnerabilities?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main():
    all_records = []
    page = 1
    while True:
        print(f"Fetching page {page}...", file=sys.stderr)
        body = fetch_page(page)
        all_records.extend(body.get("data", []))
        pagination = body.get("pagination", {})
        total_pages = pagination.get("total_pages", page)
        if page >= total_pages:
            break
        page += 1

    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(all_records, indent=2))
    print(f"Wrote {len(all_records)} records to {DATA_FILE}")


if __name__ == "__main__":
    main()
