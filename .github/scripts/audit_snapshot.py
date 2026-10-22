#!/usr/bin/env python3
"""
Full-snapshot audit: search every record in a cvelistV5 snapshot for the
keywords and queue anything the incremental scanner never evaluated.

scan_cves.py only sees records as they pass through the delta feed, so it
cannot notice records it missed (outages, a bad first run, bugs). This audit
reads the whole corpus from the daily release zip
(<date>_all_CVEs_at_midnight.zip, the inner zip of the release asset) and
diffs it against what the tracker already knows.

A matching record is new when it is not in cves/, not in seen_cve_ids or
pending_cve_ids, and not in state/audit_baseline.json. New records are added to
pending_cve_ids, so the next scan_cves.py run handles them like any other hit:
auto-merge when high-confidence, a review PR otherwise.

The baseline holds historical matches that predate the tracker (mostly apps
that call the OpenAI API) and were excluded when cves/ was seeded, so they are
not re-proposed on every audit.

Usage:
  audit_snapshot.py <inner-snapshot.zip>
Env:
  AUDIT_WRITE_BASELINE=1   record every new match in the baseline instead of
                           queuing it (one-off, to initialise the baseline)
"""

from __future__ import annotations

import json
import os
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan_cves import (  # noqa: E402
    STATE_PATH,
    is_high_confidence,
    load_cves_yaml,
    load_keywords,
    load_state,
    record_matches,
    save_state,
)

BASELINE_PATH = Path("state/audit_baseline.json")


def scan_snapshot(zip_path: str, keywords: list[str]) -> dict[str, dict]:
    """Return {cve_id: {"matches": ..., "high": bool}} for every record in the
    snapshot that matches a keyword anywhere."""
    needles = [k.encode() for k in keywords]
    hits: dict[str, dict] = {}
    with zipfile.ZipFile(zip_path) as z:
        names = [n for n in z.namelist()
                 if n.endswith(".json") and "/CVE-" in "/" + n]
        print(f"  {len(names)} record(s) in snapshot")
        for name in names:
            raw = z.read(name)
            low = raw.lower()
            # Cheap byte prefilter; record_matches decides where it matched.
            if not any(n in low for n in needles):
                continue
            record = json.loads(raw)
            cve_id = record.get("cveMetadata", {}).get("cveId")
            matches = record_matches(record, keywords)
            if cve_id and matches:
                hits[cve_id] = {"matches": matches,
                                "high": is_high_confidence(matches)}
    return hits


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    write_baseline = os.environ.get("AUDIT_WRITE_BASELINE") == "1"

    keywords = load_keywords()
    hits = scan_snapshot(sys.argv[1], keywords)
    print(f"  {len(hits)} matching record(s)")

    tracked = {e.get("cve") for e in load_cves_yaml()}
    state = load_state()
    seen = set(state.get("seen_cve_ids", []))
    pending = set(state.get("pending_cve_ids", []))
    baseline = set()
    if BASELINE_PATH.exists():
        baseline = set(json.loads(BASELINE_PATH.read_text()).get("reviewed_cve_ids", []))

    new = sorted(c for c in hits
                 if c not in tracked and c not in seen
                 and c not in pending and c not in baseline)

    lines = []
    for cve_id in new:
        h = hits[cve_id]
        where = "; ".join(f"{loc}: {','.join(dict.fromkeys(kws))}"
                          for loc, kws in h["matches"].items())
        lines.append(f"- {cve_id} ({'high' if h['high'] else 'review'}) -> {where}")
    print(f"  {len(new)} new match(es) the scanner never evaluated")
    print("\n".join(lines))

    if write_baseline:
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(json.dumps(
            {"reviewed_cve_ids": sorted(baseline | set(new))}, indent=2) + "\n")
        print(f"  baseline now holds {len(baseline | set(new))} id(s)")
        return 0

    if new:
        state["pending_cve_ids"] = sorted(pending | set(new))
        save_state(state)
        print(f"  queued {len(new)} id(s) in {STATE_PATH} pending_cve_ids")
        if any(hits[c]["high"] for c in new):
            print("::warning::snapshot audit found high-confidence CVEs the "
                  "scanner missed; queued for the next scan")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"## Snapshot audit\n\n{len(hits)} matching record(s), "
                    f"{len(new)} new (queued for the scanner).\n\n")
            f.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
