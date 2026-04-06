#!/usr/bin/env python3
"""
Threat Intelligence Aggregator for Onyx Security Knowledge Base

Fetches vulnerability and threat intelligence from multiple sources and uploads
to Onyx for RAG-based security analysis.

Usage:
    python threat_intel_aggregator.py --list-feeds
    python threat_intel_aggregator.py --fetch --feed <feed_name>
    python threat_intel_aggregator.py --fetch-all
    python threat_intel_aggregator.py --dry-run

Sources:
    - CISA KEV: Known Exploited Vulnerabilities catalog (confirmed active)
    - NVD API: National Vulnerability Database (via NIST REST API)
      - nvd_security_advisories: Recent security advisories via keyword search
      - nvd_ics_advisories: ICS/OT/SCADA vulnerabilities
      - nvd_medical_advisories: Medical/healthcare device vulnerabilities

NOTE: CISA advisories, ICS, and medical JSON feeds are HTTP 404 (federal funding lapse).
      Replaced with NVD API keyword-based search feeds.

Requirements:
    pip install requests
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

venv_path = Path(__file__).parent.parent / ".venv"
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "lib" / "python3.12" / "site-packages"))

# ─── Feed Definitions ─────────────────────────────────────────────────────────

# CISA KEV is confirmed active (HTTP 200 as of April 2026).
# CISA advisories/ICS/medical feeds return HTTP 404 (federal funding lapse).
# NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0) is used as replacement.
# Rate limit: 10 req/30s without API key, 50 req/30s with API key.
# Set NVD_API_KEY env var for higher rate limits.

# NVD API base URL
CVE_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

FEEDS = {
    # CISA KEV - CONFIRMED ACTIVE
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities (ACTIVE)",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "description": "CISA catalog of known exploited vulnerabilities (1557+ entries, updated daily)",
        "category": "Known Exploited",
        "tags": ["CISA", "KEV", "exploited", "CVE"],
        "source": "CISA",
    },

    # NVD-based feeds (replacements for deprecated CISA feeds)
    "nvd_security_advisories": {
        "name": "NVD Security Advisories (via NIST API)",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "description": "Recent security vulnerability advisories from NIST National Vulnerability Database",
        "category": "Advisories",
        "tags": ["NIST", "NVD", "CVE", "vulnerability", "advisory"],
        "source": "NVD",
        "nvd_keyword": "vulnerability security patch exploit",
        "nvd_max_results": 500,
    },
    "nvd_ics_advisories": {
        "name": "NVD ICS/OT Security Advisories (via NIST API)",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "description": "Industrial Control Systems, SCADA, and OT security vulnerabilities from NVD",
        "category": "ICS Security",
        "tags": ["NVD", "ICS", "SCADA", "OT", "industrial", "control"],
        "source": "NVD",
        "nvd_keyword": "SCADA",
        "nvd_max_results": 200,
    },
    "nvd_medical_advisories": {
        "name": "NVD Medical/Healthcare Advisories (via NIST API)",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "description": "Medical device, healthcare, and hospital security vulnerabilities from NVD",
        "category": "Healthcare Security",
        "tags": ["NVD", "medical", "healthcare", "hospital", "device"],
        "source": "NVD",
        "nvd_keyword": "medical device",
        "nvd_max_results": 200,
    },

    # DEPRECATED - kept for reference, will be skipped
    "cisa_advisories": {
        "name": "CISA Cybersecurity Advisories (DEPRECATED - 404)",
        "url": "https://www.cisa.gov/sites/default/files/feeds/cybersecurity_advisories.json",
        "description": "DEPRECATED: CISA operational directives. Use nvd_security_advisories instead.",
        "category": "Advisories",
        "tags": ["CISA", "advisory", "directive"],
        "source": "CISA",
        "deprecated": True,
    },
    "cisa_ics_advisories": {
        "name": "CISA ICS Advisories (DEPRECATED - 404)",
        "url": "https://www.cisa.gov/sites/default/files/feeds/ics_advisories.json",
        "description": "DEPRECATED: CISA ICS advisories. Use nvd_ics_advisories instead.",
        "category": "ICS Security",
        "tags": ["CISA", "ICS", "SCADA", "OT"],
        "source": "CISA",
        "deprecated": True,
    },
    "cisa_medical_advisories": {
        "name": "CISA Medical Advisories (DEPRECATED - 404)",
        "url": "https://www.cisa.gov/sites/default/files/feeds/medical_advisories.json",
        "description": "DEPRECATED: CISA medical advisories. Use nvd_medical_advisories instead.",
        "category": "Healthcare Security",
        "tags": ["CISA", "medical", "healthcare", "FDA"],
        "source": "CISA",
        "deprecated": True,
    },
}

# ─── NVD API Fetcher ─────────────────────────────────────────────────────────

def fetch_nvd_feed(
    keyword: str,
    max_results: int = 500,
    api_key: str | None = None,
    timeout: int = 30,
) -> list[dict]:
    """
    Fetch CVEs from NVD API using keyword search.
    Handles pagination automatically within rate limits.

    Args:
        keyword: Search keyword(s) for CVE matching
        max_results: Maximum number of results to fetch
        api_key: NVD API key for higher rate limits (optional)
        timeout: Request timeout in seconds

    Returns:
        List of CVE vulnerability dictionaries
    """
    api_key = api_key or os.environ.get("NVD_API_KEY")

    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    # NVD returns max 2000 per request; use 500 per page for reasonable chunks
    page_size = min(500, max_results)

    headers_req = dict(headers)  # copy for mutation
    all_vulnerabilities = []
    start_index = 0

    print(f"  Searching NVD for: '{keyword}' (max {max_results})")
    if api_key:
        print(f"  [INFO] Using NVD API key (50 req/30s)")
    else:
        print(f"  [INFO] No API key (10 req/30s) - will add delays")

    while len(all_vulnerabilities) < max_results:
        remaining = max_results - len(all_vulnerabilities)
        current_page_size = min(page_size, remaining)

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": current_page_size,
            "startIndex": start_index,
        }

        try:
            resp = requests.get(
                CVE_API_BASE,
                params=params,
                headers=headers_req,
                timeout=timeout
            )

            if resp.status_code != 200:
                print(f"  [ERROR] NVD API HTTP {resp.status_code}: {resp.text[:100]}")
                break

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            if start_index == 0:
                print(f"  [OK] NVD reports {total} total matches")

            all_vulnerabilities.extend(vulns)

            fetched = len(all_vulnerabilities)
            print(f"  Fetched {fetched}/{min(total, max_results)} CVEs...")

            # Check if we've reached the end
            if fetched >= total or len(vulns) < current_page_size:
                break

            start_index += current_page_size

            # Rate limiting: 10 req/30s without key, 50 req/30s with key
            if api_key:
                pass  # no delay needed
            else:
                time.sleep(3.5)  # 3.5s between requests (slightly conservative)

        except Exception as e:
            print(f"  [ERROR] NVD API request failed: {e}")
            break

    print(f"  [OK] Fetched {len(all_vulnerabilities)} CVEs from NVD")
    return all_vulnerabilities[:max_results]


def parse_nvd_cve(vuln: dict) -> dict:
    """
    Parse a single NVD CVE record into a structured dict for markdown generation.

    Args:
        vuln: Raw vulnerability dict from NVD API

    Returns:
        Dict with cve_id, title, content (markdown), and metadata
    """
    cve_data = vuln.get("cve", {})

    cve_id = cve_data.get("id", "Unknown")
    published = cve_data.get("published", "")[:10]
    last_modified = cve_data.get("lastModified", "")[:10]
    vuln_status = cve_data.get("vulnStatus", "Unknown")

    # Description (English preferred)
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description:
        description = descriptions[0].get("value", "No description available.") if descriptions else "No description available."

    # CVSS scores
    cvss_v31 = None
    cvss_v30 = None
    cvss_v2 = None
    metrics = cve_data.get("metrics", {})
    if metrics.get("cvssMetricV31"):
        v31 = metrics["cvssMetricV31"]
        if v31:
            cvss_v31 = v31[0].get("cvssData", {})
    if metrics.get("cvssMetricV30"):
        v30 = metrics["cvssMetricV30"]
        if v30:
            cvss_v30 = v30[0].get("cvssData", {})
    if metrics.get("cvssMetricV2"):
        v2 = metrics["cvssMetricV2"]
        if v2:
            cvss_v2 = v2[0].get("cvssData", {})

    cvss_str = ""
    if cvss_v31:
        score = cvss_v31.get("baseScore", "N/A")
        severity = cvss_v31.get("baseSeverity", "N/A")
        vector = cvss_v31.get("vectorString", "")
        cvss_str = f"CVSS 3.1: {score} ({severity}) {vector}"
    elif cvss_v30:
        score = cvss_v30.get("baseScore", "N/A")
        severity = cvss_v30.get("baseSeverity", "N/A")
        cvss_str = f"CVSS 3.0: {score} ({severity})"
    elif cvss_v2:
        score = cvss_v2.get("baseScore", "N/A")
        cvss_str = f"CVSS 2.0: {score}"

    # CPE configurations (affected products)
    cpes = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", False):
                    cpes.append(cpe_match.get("criteria", ""))

    # References
    references = []
    for ref in cve_data.get("references", [])[:10]:
        references.append(f"- [{ref.get('url', 'N/A')}]({ref.get('url', '')}) - {ref.get('sourceIdentifier', '')}")

    # CWE
    weaknesses = cve_data.get("weaknesses", [])
    cwe_list = []
    for weakness in weaknesses:
        for cwe in weakness.get("value", []):
            if cwe.startswith("CWE-"):
                cwe_list.append(cwe)

    # Build markdown
    content = f"""# {cve_id}: {description[:100]}{"..." if len(description) > 100 else ""}

## Basic Information
- **CVE ID**: {cve_id}
- **Published**: {published}
- **Last Modified**: {last_modified}
- **Status**: {vuln_status}
- **CVSS Score**: {cvss_str}

## Description
{description}

"""

    if cwe_list:
        content += f"""## CWE Classifications
{', '.join(cwe_list)}

"""

    if cvss_str:
        base_score = (cvss_v31.get("baseScore") if cvss_v31 else None) or (cvss_v30.get("baseScore") if cvss_v30 else None) or (cvss_v2.get("baseScore") if cvss_v2 else None) or "N/A"
        if cvss_v31:
            content += f"""## CVSS Details
- **Base Score**: {base_score}
- **Base Severity**: {cvss_v31.get('baseSeverity', cvss_v30.get('baseSeverity', 'N/A') if cvss_v30 else 'N/A')}
"""
            if cvss_v31.get("vectorString"):
                content += f"- **Vector**: {cvss_v31['vectorString']}\n"
            if cvss_v31.get("attackVector"):
                content += f"- **Attack Vector**: {cvss_v31.get('attackVector', 'N/A')}\n"
            if cvss_v31.get("attackComplexity"):
                content += f"- **Attack Complexity**: {cvss_v31.get('attackComplexity', 'N/A')}\n"
            if cvss_v31.get("privilegesRequired"):
                content += f"- **Privileges Required**: {cvss_v31.get('privilegesRequired', 'N/A')}\n"
            if cvss_v31.get("userInteraction"):
                content += f"- **User Interaction**: {cvss_v31.get('userInteraction', 'N/A')}\n"
            if cvss_v31.get("confidentialityImpact"):
                content += f"- **Confidentiality Impact**: {cvss_v31.get('confidentialityImpact', 'N/A')}\n"
            if cvss_v31.get("integrityImpact"):
                content += f"- **Integrity Impact**: {cvss_v31.get('integrityImpact', 'N/A')}\n"
            if cvss_v31.get("availabilityImpact"):
                content += f"- **Availability Impact**: {cvss_v31.get('availabilityImpact', 'N/A')}\n"
            content += "\n"

    if cpes[:10]:
        content += f"""## Affected Products (CPE)
"""
        for cpe in cpes[:10]:
            content += f"- `{cpe}`\n"
        if len(cpes) > 10:
            content += f"- ... and {len(cpes) - 10} more affected products\n"
        content += "\n"

    if references:
        content += f"""## References
"""
        for ref in references:
            content += f"{ref}\n"

    content += f"""
---
*Source: NIST National Vulnerability Database (NVD)*
*Retrieved: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}*
"""

    return {
        "cve_id": cve_id,
        "title": f"{cve_id}: {description[:100]}{'...' if len(description) > 100 else ''}",
        "content": content,
        "category": "NVD",
        "severity": (cvss_v31 or {}).get("baseSeverity") or (cvss_v30 or {}).get("baseSeverity") or (cvss_v2 or {}).get("baseSeverity") or "N/A",
        "cvss_score": (cvss_v31 or {}).get("baseScore", (cvss_v30 or {}).get("baseScore", (cvss_v2 or {}).get("baseScore"))),
        "published_date": published,
        "tags": ["NVD", "CVE", "NIST"] + cwe_list[:3],
        "source": "NVD",
        "doc_updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ─── CISA KEV Parser ───────────────────────────────────────────────────────────


def fetch_cve_info(cve_id: str, api_key: str | None = None, timeout: int = 30) -> dict | None:
    """Fetch CVE details from NVD API."""
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(
            CVE_API_BASE,
            params={"cveId": cve_id, "resultsPerPage": 1},
            headers=headers,
            timeout=timeout
        )
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 403 and not api_key:
            print(f"  [WARN] Rate limited without API key, skipping CVE details")
            return None
        return None
    except Exception:
        return None


def parse_cisa_kev(data: dict) -> list[dict]:
    """Parse CISA KEV catalog into vulnerability records."""
    vulnerabilities = []
    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cveID", "")
        vuln = item.get("vulnerability", {})

        # Parse date
        date_added = vuln.get("dateAdded", "")
        due_date = vuln.get("dueDate", "")

        # Build markdown content
        content = f"""# {cve_id}: {vuln.get('shortDescription', 'N/A')}

## Basic Information
- **CVE ID**: {cve_id}
- **Date Added**: {date_added}
- **Due Date**: {due_date}
- **Vendor/Project**: {vuln.get('vendorProject', 'N/A')}
- **Product**: {vuln.get('product', 'N/A')}
- **Vulnerability Name**: {vuln.get('vulnerabilityName', 'N/A')}

## Description
{vuln.get('shortDescription', 'No description available.')}

## Required Action
{vuln.get('requiredAction', 'Apply security updates or mitigations.')}

## Known Evaluation
{vuln.get('knownRansomwareCampaignUse', 'Unknown')}

## Technical Details
- **CWE**: {vuln.get('weaknesses', 'N/A')}
- **Notes**: {vuln.get('notes', 'N/A')}

## Priority Classification
- **Severity**: CRITICAL (Known Exploited)
- **Response SLA**: Within 24 hours (CISA Mandate)
- **Category**: {vuln.get('vulnerabilityName', 'Known Exploited Vulnerability')}

## MITRE ATT&CK Mapping
Refer to individual CVE details for technique mappings.

## Remediation Guidance
1. Check if affected systems are present in inventory
2. Apply vendor-supplied patches immediately
3. If no patch available, implement compensating controls
4. Monitor for indicators of compromise (IoC)
5. Report any exploitation attempts to CISA

---
*Source: CISA Known Exploited Vulnerabilities Catalog*
*Last Updated: {date_added}*
"""

        vulnerabilities.append({
            "cve_id": cve_id,
            "title": f"{cve_id}: {vuln.get('shortDescription', 'Known Exploited')[:100]}",
            "content": content,
            "category": "CISA KEV",
            "severity": "CRITICAL",
            "date_added": date_added,
            "due_date": due_date,
            "vendor": vuln.get("vendorProject", ""),
            "product": vuln.get("product", ""),
            "tags": ["CISA", "KEV", "known-exploited", "critical"],
            "doc_updated_at": date_added or "2026-01-01T00:00:00Z",
        })
    return vulnerabilities


def parse_cisa_advisories(data: dict) -> list[dict]:
    """Parse CISA advisories into document records."""
    advisories = []
    for item in data.get("advisories", []):
        advisory_id = item.get("advisoryId", "")
        title = item.get("advisoryTitle", item.get("advisoryId", ""))

        content = f"""# {title}

## Advisory Information
- **Advisory ID**: {advisory_id}
- **Initial Publication Date**: {item.get('initialPublicationDate', 'N/A')}
- **Last Reviewed**: {item.get('lastReviewedDate', 'N/A')}

## Summary
{item.get('description', 'No description available.')}

## Threat Intelligence
- **Threat Category**: {item.get('threats', [{}])[0].get('type', 'N/A') if item.get('threats') else 'N/A'}
- **Threat Date**: {item.get('threats', [{}])[0].get('date', 'N/A') if item.get('threats') else 'N/A'}

## Related Vulnerabilities
"""

        for ref in item.get('cveIDs', [])[:20]:
            content += f"- {ref}\n"

        content += f"""
## Known Affected Products
"""
        for product in item.get('knownAffectedProducts', [])[:30]:
            content += f"- {product}\n"

        content += f"""
## Resolution
{item.get('resolution', 'Apply vendor-supplied security updates.')}

## Patch Information
"""
        for patch in item.get('patchLinks', [])[:10]:
            content += f"- [{patch.get('link', 'N/A')}]({patch.get('link', '')}): {patch.get('name', 'Patch')}\n"

        content += f"""
## References
"""
        for ref in item.get('references', [])[:10]:
            content += f"- {ref}\n"

        advisories.append({
            "advisory_id": advisory_id,
            "title": title,
            "content": content,
            "category": "CISA Advisory",
            "severity": item.get('severity', 'MEDIUM'),
            "publication_date": item.get("initialPublicationDate", ""),
            "tags": ["CISA", "advisory", "directive"],
            "doc_updated_at": item.get("lastReviewedDate", "2026-01-01T00:00:00Z"),
        })
    return advisories


def build_kev_summary(data: dict) -> str:
    """Build a summary document of the CISA KEV catalog."""
    vulnerabilities = data.get("vulnerabilities", [])
    total = len(vulnerabilities)

    # Count by date
    recent = []
    for item in vulnerabilities:
        date_added = item.get("vulnerability", {}).get("dateAdded", "")
        if date_added and date_added.startswith("2026"):
            recent.append(item)

    # Count by vendor
    vendors = {}
    for item in vulnerabilities:
        vendor = item.get("vulnerability", {}).get("vendorProject", "Unknown")
        vendors[vendor] = vendors.get(vendor, 0) + 1

    top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]

    content = f"""# CISA Known Exploited Vulnerabilities (KEV) Catalog Summary

## Overview
- **Total Known Exploited Vulnerabilities**: {total}
- **Catalog Last Updated**: {data.get('title', 'N/A')}
- **Source**: CISA.gov

## Recent Additions (2026)
{len(recent)} vulnerabilities added in 2026

## Top Affected Vendors
"""
    for vendor, count in top_vendors:
        content += f"- **{vendor}**: {count} vulnerabilities\n"

    content += f"""
## Priority Guidance

### Immediate Action Required
All vulnerabilities in the KEV catalog are considered critical and actively exploited.
Per CISA Binding Operational Directive 22-01, federal agencies must remediate KEV
vulnerabilities according to the due dates specified in the catalog.

### Remediation Prioritization
1. **Ransomware-associated CVEs**: Check CISA guidance on known ransomware use
2. **Remote code execution (RCE)**: Prioritize network-facing services
3. **Privilege escalation**: Focus on domain controllers and critical infrastructure
4. **Data exfiltration**: Prioritize databases and file servers

### Compensating Controls
If patches are not available:
- Implement network segmentation
- Deploy intrusion detection/prevention systems
- Enable enhanced logging and monitoring
- Restrict access to affected systems
- Consider removal from network if risk is unacceptable

## How to Use This Catalog

1. **Cross-reference** with your asset inventory
2. **Prioritize** by exploit availability and network exposure
3. **Automate** detection using vulnerability scanners
4. **Track** remediation progress in your ticketing system

## Related Documents
- Individual CVE detail documents in this knowledge base
- MITRE ATT&CK Framework (for technique mapping)
- NIST SP 800-40 Enterprise Patch Management Guide

---
*Source: CISA Known Exploited Vulnerabilities Catalog*
*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}`
"""

    return content


def build_advisory_summary(data: dict, feed_key: str) -> str:
    """Build a summary document for CISA advisories."""
    advisories = data.get("advisories", [])
    feed = FEEDS.get(feed_key, {})

    content = f"""# {feed.get('name', 'CISA Advisories')} Summary

## Overview
- **Total Advisories**: {len(advisories)}
- **Source**: {feed.get('url', 'CISA.gov')}

## Advisory Categories
"""
    # Group by category/type
    categories = {}
    severities = {}
    for item in advisories:
        cat = item.get("advisoryId", "").split("-")[0] if "-" in item.get("advisoryId", "") else "General"
        categories[cat] = categories.get(cat, 0) + 1
        sev = item.get("severity", "Unknown")
        severities[sev] = severities.get(sev, 0) + 1

    content += "\n### By Category\n"
    for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        content += f"- **{cat}**: {count} advisories\n"

    content += "\n### By Severity\n"
    for sev, count in sorted(severities.items(), key=lambda x: x[1], reverse=True):
        content += f"- **{sev}**: {count} advisories\n"

    content += """
## Remediation Steps
1. Review each advisory for applicability to your environment
2. Identify affected products in your asset inventory
3. Apply patches or mitigations per vendor guidance
4. Verify remediation through testing
5. Document findings and residual risks

---
*Source: CISA Cybersecurity Advisories*
*Generated: """ + datetime.now(timezone.utc).strftime('%Y-%m-%d') + "*\n"

    return content


def build_nvd_summary(records: list[dict], feed: dict) -> str:
    """Build a summary document for NVD-based feeds."""
    total = len(records)

    # Count by severity
    severities: dict[str, int] = {}
    # Count by year
    years: dict[str, int] = {}
    # Count by CVSS score range
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    none_na_count = 0

    for record in records:
        sev = record.get("severity", "N/A")
        if sev in ("CRITICAL", "CRITICAL"):
            critical_count += 1
        elif sev == "HIGH":
            high_count += 1
        elif sev == "MEDIUM":
            medium_count += 1
        elif sev == "LOW":
            low_count += 1
        else:
            none_na_count += 1

        pub_date = record.get("published_date", "")
        if pub_date and len(pub_date) >= 4:
            year = pub_date[:4]
            years[year] = years.get(year, 0) + 1

    content = f"""# {feed['name']} Summary

## Overview
- **Total Records**: {total}
- **Source**: NIST National Vulnerability Database (NVD) API
- **Search Keywords**: {feed.get('nvd_keyword', 'N/A')}
- **Retrieved**: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}

## Severity Distribution
- **CRITICAL**: {critical_count}
- **HIGH**: {high_count}
- **MEDIUM**: {medium_count}
- **LOW**: {low_count}
- **N/A**: {none_na_count}

"""

    if years:
        content += "## Records by Publication Year\n"
        for year in sorted(years.keys(), reverse=True):
            content += f"- **{year}**: {years[year]} vulnerabilities\n"
        content += "\n"

    content += f"""## Top CVEs (by CVSS score)

"""
    # Show top 10 by CVSS score
    scored = [(r.get("cvss_score"), r) for r in records if r.get("cvss_score") is not None]
    scored.sort(key=lambda x: x[0] or 0, reverse=True)
    for score, record in scored[:10]:
        content += f"- **{record['cve_id']}** — CVSS {score}: {record.get('title', '')[:80]}\n"

    content += f"""
## How to Use This Data

1. **Prioritize** by CVSS score — focus on CRITICAL and HIGH severity items
2. **Cross-reference** CVE IDs with your software inventory
3. **Check affected products** (CPE) in individual records
4. **Review references** for patches and mitigation guidance
5. **Track** new vulnerabilities via regular feed updates

## Remediation Guidance

- **CRITICAL/HIGH**: Apply patches within 24–72 hours
- **MEDIUM**: Apply patches within 30 days
- **LOW**: Plan remediation within 90 days
- **No patch available**: Implement compensating controls (network segmentation, WAF, IDS)

## Related Documents

- Individual CVE detail documents in this knowledge base
- NIST SP 800-40 Enterprise Patch Management Guide
- CISA KEV Catalog (known exploited vulnerabilities)

---
*Source: NIST National Vulnerability Database (NVD)*
*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}*
"""
    return content


# ─── Onyx Upload ───────────────────────────────────────────────────────────────

def login(base_url: str, email: str, password: str) -> str | None:
    """Login and return the auth cookie value."""
    try:
        resp = requests.post(
            f"{base_url}/auth/login",
            data={"username": email, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        if resp.status_code == 204:
            cookie = resp.headers.get("set-cookie", "")
            for part in cookie.split(","):
                part = part.strip()
                if "fastapiusersauth=" in part:
                    return part.split(";")[0].split("=")[1]
        return None
    except Exception as e:
        print(f"  [ERROR] Login failed: {e}")
        return None


def upload_document(base_url: str, cookie: str, doc: dict, dry_run: bool = False) -> dict:
    """Upload a document to Onyx."""
    if dry_run:
        print(f"  [DRY RUN] {doc.get('semantic_identifier', 'untitled')}")
        return {"status": "dry_run"}

    payload = {
        "document": {
            "sections": [{"text": doc["content"], "link": ""}],
            "semantic_identifier": doc["semantic_identifier"],
            "metadata": {
                "category": doc.get("category", "threat-intel"),
                "source": doc.get("source", "threat-intelligence"),
                "cve_id": doc.get("cve_id", ""),
                "advisory_id": doc.get("advisory_id", ""),
                "severity": doc.get("severity", ""),
                "vendor": doc.get("vendor", ""),
                "tags": ",".join(doc.get("tags", [])),
            },
            "doc_updated_at": doc.get("doc_updated_at", "2026-01-01T00:00:00Z"),
            "primary_owners": [],
            "secondary_owners": [],
            "title": doc.get("title", doc["semantic_identifier"]),
        }
    }

    try:
        resp = requests.post(
            f"{base_url}/onyx-api/ingestion",
            json=payload,
            cookies={"fastapiusersauth": cookie},
            timeout=60
        )
        if resp.status_code == 200:
            result = resp.json()
            action = "updated" if result.get("already_existed") else "uploaded"
            return {"status": "ok", "action": action}
        else:
            return {"status": "error", "code": resp.status_code, "msg": resp.text[:100]}
    except Exception as e:
        return {"status": "error", "msg": str(e)}


def save_to_kb_dir(records: list[dict], category: str, dry_run: bool = False) -> int:
    """Save records as markdown files to knowledge-base directory."""
    kb_dir = Path(__file__).parent.parent
    output_dir = kb_dir / "威胁情报" / "feeds"
    output_dir.mkdir(parents=True, exist_ok=True)

    if dry_run:
        print(f"  [DRY RUN] Would save {len(records)} files to {output_dir}")
        return len(records)

    saved = 0
    for record in records:
        # Generate filename
        cve_id = record.get("cve_id", "")
        advisory_id = record.get("advisory_id", "")

        if cve_id:
            filename = f"{cve_id.replace('-', '_')}.md"
        elif advisory_id:
            safe_id = advisory_id.replace("/", "_").replace(":", "_")
            filename = f"{safe_id}.md"
        else:
            # Use title as filename
            title = record.get("title", "untitled")
            safe_title = "".join(c for c in title[:50] if c.isalnum() or c in " -_").strip()
            filename = f"{safe_title[:50]}.md"

        filepath = output_dir / filename

        # Read existing to avoid duplicate if not changed
        existing_content = ""
        if filepath.exists():
            existing_content = filepath.read_text(encoding="utf-8")

        if existing_content != record.get("content", ""):
            filepath.write_text(record.get("content", ""), encoding="utf-8")
            saved += 1

    return saved


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator for Onyx Security Knowledge Base"
    )
    parser.add_argument("--url", default=os.environ.get("ONYX_URL", "http://localhost:8080"))
    parser.add_argument("--email", default=os.environ.get("ONYX_EMAIL", "security-admin@onyx.local"))
    parser.add_argument("--password", default=os.environ.get("ONYX_PASSWORD", "admin123"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list-feeds", action="store_true")
    parser.add_argument("--fetch", action="store_true", help="Fetch a specific feed")
    parser.add_argument("--feed", choices=list(FEEDS.keys()), help="Feed name")
    parser.add_argument("--fetch-all", action="store_true", help="Fetch all feeds")
    parser.add_argument("--skip-onyx", action="store_true", help="Skip Onyx upload, save locally only")
    parser.add_argument("--output-dir", default=None, help="Override output directory")
    args = parser.parse_args()

    if args.list_feeds:
        print("Available threat intelligence feeds:\n")
        for key, feed in FEEDS.items():
            print(f"  {key}")
            print(f"    Name: {feed['name']}")
            print(f"    URL: {feed['url']}")
            print(f"    Description: {feed['description']}")
            print(f"    Category: {feed['category']}")
            print()
        print("Also: CVE search via NVD API (use --fetch with cve_id)")
        return

    if not (args.fetch or args.fetch_all):
        parser.print_help()
        print("\nExamples:")
        print("  python threat_intel_aggregator.py --list-feeds")
        print("  python threat_intel_aggregator.py --fetch --feed cisa_kev")
        print("  python threat_intel_aggregator.py --fetch-all")
        print("  python threat_intel_aggregator.py --fetch --feed cisa_kev --dry-run")
        return

    # Determine feeds to process
    if args.fetch_all:
        feeds_to_process = list(FEEDS.keys())
    elif args.feed:
        feeds_to_process = [args.feed]
    else:
        print("[ERROR] Specify --feed <name> or --fetch-all")
        return

    print(f"Processing {len(feeds_to_process)} feed(s): {feeds_to_process}\n")

    # Login to Onyx
    cookie = None
    if not args.skip_onyx:
        print(f"Logging in as {args.email}...")
        cookie = login(args.url, args.email, args.password)
        if not cookie:
            print("[WARN] Onyx login failed, saving locally only")
        else:
            print("[OK] Logged in.\n")

    total_results = 0
    total_uploaded = 0

    for feed_key in feeds_to_process:
        feed = FEEDS[feed_key]

        # Skip deprecated feeds
        if feed.get("deprecated"):
            # Map old CISA feed keys to NVD replacements
            replacements = {
                "cisa_advisories": "nvd_security_advisories",
                "cisa_ics_advisories": "nvd_ics_advisories",
                "cisa_medical_advisories": "nvd_medical_advisories",
            }
            replacement = replacements.get(feed_key, feed_key.replace("cisa_", "nvd_"))
            print(f"\n{'='*60}")
            print(f"Skipping deprecated feed: {feed['name']}")
            print(f"  Use '--feed {replacement}' instead")
            print(f"{'='*60}")
            continue

        print(f"\n{'='*60}")
        print(f"Processing: {feed['name']}")
        print(f"{'='*60}")

        # ── NVD-based feeds ──────────────────────────────────────────────
        if feed_key.startswith("nvd_"):
            api_key = os.environ.get("NVD_API_KEY")
            vulns = fetch_nvd_feed(
                keyword=feed["nvd_keyword"],
                max_results=feed.get("nvd_max_results", 500),
                api_key=api_key,
            )
            if not vulns:
                print(f"  [SKIP] Could not fetch {feed_key}")
                continue

            records = [parse_nvd_cve(v) for v in vulns]

            # Build summary
            summary_content = build_nvd_summary(records, feed)
            summary_record = {
                "semantic_identifier": f"{feed_key.upper()}_Summary",
                "title": f"{feed['name']} Summary",
                "content": summary_content,
                "category": feed["category"],
                "severity": "HIGH",
                "tags": feed["tags"],
                "source": "threat-intelligence",
                "doc_updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }

        # ── CISA KEV ────────────────────────────────────────────────────
        elif feed_key == "cisa_kev":
            print(f"  Fetching CISA KEV catalog...")
            try:
                resp = requests.get(feed["url"], timeout=60)
                if resp.status_code != 200:
                    print(f"  [ERROR] HTTP {resp.status_code}")
                    continue
                data = resp.json()
                vuln_count = len(data.get("vulnerabilities", []))
                print(f"  [OK] Fetched {vuln_count} CISA KEV entries")
            except Exception as e:
                print(f"  [ERROR] {e}")
                continue

            records = parse_cisa_kev(data)

            # Also build summary
            summary_content = build_kev_summary(data)
            summary_record = {
                "semantic_identifier": "CISA_KEV_Catalog_Summary",
                "title": "CISA KEV Catalog Summary",
                "content": summary_content,
                "category": "CISA KEV",
                "severity": "CRITICAL",
                "tags": ["CISA", "KEV", "summary"],
                "source": "threat-intelligence",
                "doc_updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }

        else:
            print(f"  [SKIP] No parser for {feed_key}")
            continue

        print(f"\n  Parsed {len(records)} vulnerability records")

        # Save locally
        saved = save_to_kb_dir(records, feed["category"], dry_run=args.dry_run)
        print(f"  Saved {saved} new files locally")

        # Upload summary
        if cookie and not args.dry_run:
            result = upload_document(args.url, cookie, summary_record, dry_run=args.dry_run)
            if result.get("status") == "ok":
                print(f"  [OK] Uploaded summary: {result.get('action')}")

        # Upload individual records (with rate limiting)
        if cookie and not args.dry_run:
            print(f"\n  Uploading {len(records)} records to Onyx...")
            for i, record in enumerate(records):
                result = upload_document(
                    args.url, cookie,
                    {
                        **record,
                        "semantic_identifier": f"{record.get('cve_id', record.get('advisory_id', ''))}_threat_intel",
                        "source": "threat-intelligence",
                    },
                    dry_run=args.dry_run
                )
                if result.get("status") == "ok":
                    total_uploaded += 1
                elif result.get("status") == "error":
                    print(f"    [ERROR] {record.get('cve_id', record.get('advisory_id', ''))}: {result.get('msg', '')}")

                # Rate limiting: 1 second between requests
                if (i + 1) % 10 == 0:
                    print(f"    ... {i + 1}/{len(records)} uploaded")
                    time.sleep(1)
        elif args.dry_run:
            print(f"  [DRY RUN] Would upload {len(records)} records to Onyx")

        total_results += len(records)

    print(f"\n{'='*60}")
    print(f"Summary:")
    print(f"  Total records processed: {total_results}")
    print(f"  Total uploaded to Onyx: {total_uploaded}")
    print(f"  Mode: {'DRY RUN' if args.dry_run else 'LIVE'}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
