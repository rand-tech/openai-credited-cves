#!/usr/bin/env python3
"""
Mark tracked CVEs that appear in the CISA KEV (Known Exploited Vulnerabilities)
catalog.

Pulls the full catalog once (a single public JSON feed, no API key), then
cross-references it against cves/. For every tracked CVE that is in KEV it sets:

    cisa_kev: true
    kev_date_added: 'YYYY-MM-DD'   # date CISA added it to KEV

and it removes those fields from any record no longer in KEV, so the marker
stays accurate.

Authoritative data enrichment of existing records — like backfill_cvss.py, it
writes straight to cves/ and lets the workflow commit to main. Declarative and
idempotent: unchanged records are rewritten byte-identical (no churn), so no
state file is needed. If the feed can't be fetched the script no-ops, so a
CISA outage never strips existing markers.
"""

from __future__ import annotations

import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan_cves import CVES_DIR, http_get_json, write_cve_entry  # noqa: E402
from entry_fields import normalize  # noqa: E402  (canonical field order)

KEV_FEED_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")
KEV_FIELDS = ("cisa_kev", "kev_date_added")


def load_kev_index() -> dict[str, dict]:
    """Return {cve_id: {"date_added": 'YYYY-MM-DD'|None}} for all of CISA KEV."""
    feed = http_get_json(KEV_FEED_URL)
    return {v["cveID"]: {"date_added": (v.get("dateAdded") or "")[:10] or None}
            for v in feed.get("vulnerabilities", []) if v.get("cveID")}


def apply_kev(entry: dict, info: dict | None) -> dict | None:
    """Return the entry with KEV fields set/cleared to reflect `info`, or None
    if nothing changed (so callers can skip a byte-identical rewrite)."""
    if info:
        if (entry.get("cisa_kev") is True
                and entry.get("kev_date_added") == info["date_added"]):
            return None
        updated = dict(entry)
        updated["cisa_kev"] = True
        updated["kev_date_added"] = info["date_added"]
        return normalize(updated)
    # not in KEV: strip any stale marker
    if any(k in entry for k in KEV_FIELDS):
        return normalize({k: v for k, v in entry.items() if k not in KEV_FIELDS})
    return None


def main() -> int:
    try:
        kev = load_kev_index()
    except RuntimeError as e:
        print(f"::warning::CISA KEV fetch failed; skipping: {e}", file=sys.stderr)
        return 0
    if not kev:
        print("::warning::CISA KEV feed was empty; skipping.", file=sys.stderr)
        return 0
    print(f"Pulled {len(kev)} CVE(s) from CISA KEV.")

    marked = cleared = 0
    for path in sorted(CVES_DIR.glob("*.yaml")):
        entry = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(entry, dict):
            continue
        result = apply_kev(entry, kev.get(entry.get("cve")))
        if result is None:
            continue
        write_cve_entry(result)
        if result.get("cisa_kev"):
            marked += 1
            print(f"  🛑 {entry['cve']} in KEV (added {result['kev_date_added']})")
        else:
            cleared += 1
            print(f"  cleared stale KEV marker on {entry['cve']}")

    print(f"Done. {marked} KEV marker(s) set/updated, {cleared} cleared.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
