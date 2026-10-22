"""Canonical field order for cves/<ID>.yaml entries.

Keeps auto-created and patched files consistent with the rest of cves/.
"""

FIELD_ORDER = (
    "cve", "ghsa", "date", "vendor", "product", "cvss", "credit",
    "status", "cve_link", "ghsa_link",
    "cisa_kev", "kev_date_added", "notes",
    "auto_discovered",
)


def normalize(entry: dict) -> dict:
    """Return the entry with keys in FIELD_ORDER; any extra keys keep their
    relative order at the end so nothing is ever dropped."""
    ordered = {k: entry[k] for k in FIELD_ORDER if k in entry}
    for k, v in entry.items():
        if k not in ordered:
            ordered[k] = v
    return ordered
