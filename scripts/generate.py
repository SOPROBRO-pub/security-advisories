#!/usr/bin/env python3
"""Generate per-CVE markdown files and index pages from Patchstack data."""
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "all-advisories.json"
ADVISORIES_DIR = ROOT / "advisories"
FEATURED_DIR = ROOT / "featured"
README_FILE = ROOT / "README.md"

RESEARCHER_HANDLE = "SOPROBRO"
RESEARCHER_PROFILE = "https://patchstack.com/database/researchers/9b6c8f8f-33bf-41a9-8ff3-651418dddd41"


def sanitize_filename(text: str) -> str:
    """Make a filesystem-safe filename from text."""
    return re.sub(r"[^A-Za-z0-9.-]+", "-", text).strip("-").lower()


def cve_id(record: dict) -> str:
    cve = record.get("cve") or ""
    if cve and not cve.startswith("CVE-"):
        return f"CVE-{cve}"
    return cve or "NO-CVE"


def filename_for(record: dict) -> str:
    cve = cve_id(record)
    plugin = sanitize_filename(record.get("product_slug") or "unknown")
    return f"{cve}-{plugin}.md"


def patchstack_url(record: dict) -> str:
    product = record.get("product_slug", "")
    slug = record.get("slug", "")
    return f"https://patchstack.com/database/wordpress/plugin/{product}/vulnerability/{slug}"


def nvd_url(record: dict) -> str:
    cve = cve_id(record)
    if cve == "NO-CVE":
        return ""
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def format_date(iso: str) -> str:
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except Exception:
        return iso[:10]


def severity_badge(cvss) -> str:
    if cvss is None:
        return "N/A"
    if cvss >= 9.0:
        return f"{cvss} (Critical)"
    if cvss >= 7.0:
        return f"{cvss} (High)"
    if cvss >= 4.0:
        return f"{cvss} (Medium)"
    return f"{cvss} (Low)"


def render_advisory(record: dict) -> str:
    cve = cve_id(record)
    title_type = record.get("clean_title", record.get("type", "Vulnerability"))
    product = record.get("product_name", "Unknown plugin")
    nvd = nvd_url(record)
    ps_url = patchstack_url(record)

    lines = [
        f"# {title_type} in {product}",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| **CVE** | [{cve}]({nvd}) |" if nvd else f"| **CVE** | {cve} |",
        f"| **CVSS** | {severity_badge(record.get('cvss'))} |",
        f"| **Vulnerability type** | {record.get('type', '')} |",
        f"| **Affected product** | {product} ({record.get('kind', '')}) |",
        f"| **Affected versions** | `{record.get('affected_in', '')}` |",
    ]
    fixed = record.get("fixed_in")
    lines.append(f"| **Fixed in** | `{fixed}` |" if fixed else f"| **Fixed in** | (not patched at disclosure) |")
    lines.extend([
        f"| **Platform** | {record.get('platform', '')} |",
        f"| **Researcher** | [{RESEARCHER_HANDLE}]({RESEARCHER_PROFILE}) |",
        f"| **Reported** | {format_date(record.get('report_date', ''))} |",
        f"| **Disclosed** | {format_date(record.get('disclosure_date', ''))} |",
        f"| **Patch priority** | {record.get('patch_priority', 'N/A')} |",
        f"| **Exploited in the wild** | {'Yes' if record.get('is_exploited') else 'No'} |",
        "",
        "## References",
        "",
        f"- Patchstack advisory: {ps_url}",
    ])
    if nvd:
        lines.append(f"- NVD: {nvd}")
    lines.extend([
        "",
        "## Disclosure",
        "",
        f"This vulnerability was responsibly disclosed via [Patchstack's Vulnerability Disclosure Program]({RESEARCHER_PROFILE}). Patchstack coordinates with vendors and assigns CVE identifiers as a CVE Numbering Authority (CNA).",
        "",
    ])
    return "\n".join(lines)


def is_featured(record: dict) -> bool:
    """High-impact criteria: rare types OR CVSS >= 8."""
    vtype = record.get("type", "")
    rare_types = {
        "Remote Code Execution (RCE)",
        "SQL Injection",
        "Privilege Escalation",
        "Arbitrary File Deletion",
        "Broken Access Control",
        "Content Injection",
    }
    if vtype in rare_types:
        return True
    cvss = record.get("cvss") or 0
    return cvss >= 8.0


def render_year_index(year: str, records: list) -> str:
    lines = [
        f"# {year} Advisories",
        "",
        f"{len(records)} advisories disclosed in {year} by [{RESEARCHER_HANDLE}]({RESEARCHER_PROFILE}).",
        "",
        "| CVE | Plugin | Type | CVSS | Reported |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(records, key=lambda x: x.get("report_date", ""), reverse=True):
        cve = cve_id(r)
        fname = filename_for(r)
        nvd = nvd_url(r)
        cve_link = f"[{cve}]({fname})" if cve != "NO-CVE" else cve
        lines.append(
            f"| {cve_link} | {r.get('product_name', '')} | {r.get('type', '')} | {r.get('cvss', 'N/A')} | {format_date(r.get('report_date', ''))} |"
        )
    return "\n".join(lines) + "\n"


def render_featured_index(records: list) -> str:
    featured = [r for r in records if is_featured(r)]
    featured.sort(key=lambda x: (-(x.get("cvss") or 0), x.get("report_date", "")))
    lines = [
        "# Featured Advisories",
        "",
        "Hand-picked high-impact disclosures - the rare non-XSS/CSRF findings and any vulnerability with CVSS ≥ 8.0.",
        "",
        f"**{len(featured)} featured** out of {len(records)} total advisories.",
        "",
        "| CVE | Plugin | Type | CVSS | Year |",
        "|---|---|---|---|---|",
    ]
    for r in featured:
        cve = cve_id(r)
        year = (r.get("report_date") or "")[:4]
        rel_path = f"../advisories/{year}/{filename_for(r)}"
        cve_link = f"[{cve}]({rel_path})"
        lines.append(
            f"| {cve_link} | {r.get('product_name', '')} | {r.get('type', '')} | **{r.get('cvss', 'N/A')}** | {year} |"
        )
    return "\n".join(lines) + "\n"


def render_main_readme(records: list) -> str:
    total = len(records)
    types = Counter(r.get("type", "") for r in records)
    years = Counter((r.get("report_date") or "")[:4] for r in records)
    cvss_scores = [r.get("cvss") for r in records if r.get("cvss") is not None]
    min_cvss = min(cvss_scores) if cvss_scores else 0
    max_cvss = max(cvss_scores) if cvss_scores else 0
    high_severity = sum(1 for c in cvss_scores if c >= 7.0)
    critical = sum(1 for c in cvss_scores if c >= 9.0)
    featured_count = sum(1 for r in records if is_featured(r))

    lines = [
        "# Security Advisories",
        "",
        f"Curated record of CVE disclosures by [**{RESEARCHER_HANDLE}**]({RESEARCHER_PROFILE}), a vulnerability researcher focused on WordPress plugin security.",
        "",
        "All disclosures listed here were responsibly reported through [Patchstack's Vulnerability Disclosure Program](https://patchstack.com/database/), which coordinates with plugin vendors and assigns CVE identifiers as an authorized CNA.",
        "",
        "## Statistics",
        "",
        f"- **Total advisories:** {total}",
        f"- **All assigned a CVE identifier**",
        f"- **CVSS range:** {min_cvss} → {max_cvss}",
        f"- **High severity (CVSS ≥ 7.0):** {high_severity}",
        f"- **Critical (CVSS ≥ 9.0):** {critical}",
        f"- **Featured (rare types or CVSS ≥ 8.0):** {featured_count} — see [`featured/`](featured/)",
        "",
        "### By year",
        "",
        "| Year | Advisories |",
        "|---|---|",
    ]
    for year, count in sorted(years.items()):
        lines.append(f"| [{year}](advisories/{year}/) | {count} |")
    lines.extend([
        "",
        "### By vulnerability type",
        "",
        "| Type | Count |",
        "|---|---|",
    ])
    for vtype, count in types.most_common():
        lines.append(f"| {vtype} | {count} |")

    lines.extend([
        "",
        "## Repository layout",
        "",
        "```",
        "security-advisories/",
        "├── README.md              # You are here",
        "├── advisories/",
        "│   ├── 2024/              # One markdown file per CVE",
        "│   └── 2025/",
        "├── featured/              # Hand-picked high-impact disclosures",
        "├── data/",
        "│   └── all-advisories.json  # Machine-readable dataset (raw API response)",
        "└── scripts/",
        "    └── generate.py        # Regenerates markdown files from data/",
        "```",
        "",
        "## Refreshing the dataset",
        "",
        "The dataset is pulled from the public Patchstack researcher profile via their internal API endpoint at `vdp-api.patchstack.com`. To refresh:",
        "",
        "```bash",
        "python3 scripts/refresh.py     # downloads latest pages to data/",
        "python3 scripts/generate.py    # regenerates markdown from data/",
        "```",
        "",
        "## Coordinated disclosure",
        "",
        "These reports follow Patchstack's coordinated disclosure process:",
        "1. Vulnerability is reported privately to Patchstack",
        "2. Patchstack works with the plugin vendor on a fix",
        "3. Public disclosure happens after the vendor releases a patch or the embargo period expires",
        "4. A CVE is assigned and pushed to NVD",
        "",
        "## Researcher",
        "",
        f"- **Handle:** [{RESEARCHER_HANDLE}]({RESEARCHER_PROFILE}) (Patchstack rank #25, Level 6)",
        "- **Focus:** WordPress plugin XSS, CSRF, and the occasional juicier finding (RCE, SQLi, access control)",
        "- **GitHub:** [@SOPROBRO-pub](https://github.com/SOPROBRO-pub)",
        "",
    ])
    return "\n".join(lines)


def main():
    with open(DATA_FILE) as f:
        records = json.load(f)

    by_year = defaultdict(list)
    for r in records:
        year = (r.get("report_date") or "0000")[:4]
        by_year[year].append(r)

    # Per-CVE files
    written = 0
    for year, recs in by_year.items():
        year_dir = ADVISORIES_DIR / year
        year_dir.mkdir(parents=True, exist_ok=True)
        for r in recs:
            (year_dir / filename_for(r)).write_text(render_advisory(r))
            written += 1
        (year_dir / "README.md").write_text(render_year_index(year, recs))

    # Featured
    FEATURED_DIR.mkdir(parents=True, exist_ok=True)
    (FEATURED_DIR / "README.md").write_text(render_featured_index(records))

    # Main README
    README_FILE.write_text(render_main_readme(records))

    print(f"Generated {written} advisory files across {len(by_year)} year(s)")
    print(f"Featured: {sum(1 for r in records if is_featured(r))} CVEs")


if __name__ == "__main__":
    main()
