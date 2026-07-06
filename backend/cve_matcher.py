"""
Matches banners/service info from scan_ports() results against a static
CSV of known vulnerable service versions, returning CVE hits.
"""
import csv
import re
import os

CSV_PATH = os.path.join(os.path.dirname(__file__), "cve_database.csv")


def load_cve_database(csv_path: str = CSV_PATH) -> list:
    entries = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append(row)
    return entries


def match_banner(banner: str, cve_db: list, known_service: str = None) -> list:
    """
    Match a banner (and optionally a known running service name, since
    some services like uhttpd don't reveal themselves in the banner)
    against the CVE database.
    """
    matches = []
    banner = banner or ""
    banner_lower = banner.lower()

    for entry in cve_db:
        service = entry["service"]
        service_lower = service.lower()

        service_present = service_lower in banner_lower or (
            known_service and known_service.lower() == service_lower
        )
        if not service_present:
            continue

        version_pattern = entry["version_pattern"]

        # Look for a version number specifically near the service name,
        # not just the first number anywhere in the banner.
        version_str = ""
        version_search = re.search(
            rf"{re.escape(service)}[\s_/-]*v?(\d+\.\d+(?:\.\d+)?)",
            banner,
            re.IGNORECASE,
        )
        if version_search:
            version_str = version_search.group(1)

        if version_pattern == ".*" or (version_str and re.match(version_pattern, version_str)):
            matches.append({
                "service": service,
                "matched_version": version_str or "unknown",
                "cve_id": entry["cve_id"],
                "severity": entry["severity"],
                "description": entry["description"],
            })

    return matches


def match_scan_results(scan_results: list, csv_path: str = CSV_PATH, service_map: dict = None) -> list:
    """
    Takes the list output of scan_ports() and returns an enriched list
    with a 'cves' field added per port.

    service_map: optional {port: service_name} for services we know we
    launched ourselves (e.g. {8888: "uhttpd"}), since not all services
    reveal their identity in the banner.
    """
    cve_db = load_cve_database(csv_path)
    service_map = service_map or {}
    enriched = []
    for entry in scan_results:
        entry_copy = dict(entry)
        known_service = service_map.get(entry["port"])
        entry_copy["cves"] = match_banner(entry.get("banner", ""), cve_db, known_service)
        enriched.append(entry_copy)
    return enriched


if __name__ == "__main__":
    import json
    sample_results = [
        {"port": 8888, "open": True, "banner": "HTTP/1.0 200 OK\r\nConnection: close"},
        {"port": 22, "open": True, "banner": "SSH-2.0-dropbear_0.52"},
    ]
    # We know port 8888 is running uhttpd because we started it ourselves
    print(json.dumps(
        match_scan_results(sample_results, service_map={8888: "uhttpd"}),
        indent=2
    ))
