# Security Advisories

Curated record of CVE disclosures by [**SOPROBRO**](https://patchstack.com/database/researchers/9b6c8f8f-33bf-41a9-8ff3-651418dddd41), a vulnerability researcher focused on WordPress plugin security.

All disclosures listed here were responsibly reported through [Patchstack's Vulnerability Disclosure Program](https://patchstack.com/database/), which coordinates with plugin vendors and assigns CVE identifiers as an authorized CNA.

## Statistics

- **Total advisories:** 747
- **All assigned a CVE identifier**
- **CVSS range:** 4.3 → 9.6
- **High severity (CVSS ≥ 7.0):** 391
- **Critical (CVSS ≥ 9.0):** 3
- **Featured (rare types or CVSS ≥ 8.0):** 11 — see [`featured/`](featured/)

### By year

| Year | Advisories |
|---|---|
| [2024](advisories/2024/) | 745 |
| [2025](advisories/2025/) | 2 |

### By vulnerability type

| Type | Count |
|---|---|
| Cross Site Scripting (XSS) | 444 |
| Cross Site Request Forgery (CSRF) | 294 |
| Broken Access Control | 4 |
| Arbitrary File Deletion | 1 |
| Privilege Escalation | 1 |
| Remote Code Execution (RCE) | 1 |
| SQL Injection | 1 |
| Content Injection | 1 |

## Repository layout

```
security-advisories/
├── README.md              # You are here
├── advisories/
│   ├── 2024/              # One markdown file per CVE
│   └── 2025/
├── featured/              # Hand-picked high-impact disclosures
└── data/
    └── all-advisories.json  # Machine-readable dataset
```

## Coordinated disclosure

These reports follow Patchstack's coordinated disclosure process:
1. Vulnerability is reported privately to Patchstack
2. Patchstack works with the plugin vendor on a fix
3. Public disclosure happens after the vendor releases a patch or the embargo period expires
4. A CVE is assigned and pushed to NVD

## Researcher

- **Handle:** [SOPROBRO](https://patchstack.com/database/researchers/9b6c8f8f-33bf-41a9-8ff3-651418dddd41) (Patchstack rank #25, Level 6)
- **Focus:** WordPress plugin XSS, CSRF, and the occasional juicier finding (RCE, SQLi, access control)
- **GitHub:** [@SOPROBRO-pub](https://github.com/SOPROBRO-pub)
