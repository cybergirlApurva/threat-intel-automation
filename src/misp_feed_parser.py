"""
misp_feed_parser.py
===================
Connects to a MISP instance, pulls recent threat events, extracts and
normalizes IOCs (IPs, domains, URLs, hashes), and exports to JSON/CSV.

Usage:
    python misp_feed_parser.py --days 7 --output samples/misp_iocs.json
    python misp_feed_parser.py --days 1 --format csv --output samples/misp_iocs.csv

Author: Apurva Tiwari
"""

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration — set via environment variables in production
# ---------------------------------------------------------------------------

MISP_URL = os.getenv("MISP_URL", "https://misp.example.com")
MISP_API_KEY = os.getenv("MISP_API_KEY", "YOUR_API_KEY_HERE")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"

# IOC types to extract from MISP attributes
SUPPORTED_ATTRIBUTE_TYPES = {
    "ip-src", "ip-dst", "ip-src|port", "ip-dst|port",
    "domain", "hostname", "url", "uri",
    "md5", "sha1", "sha256", "sha512",
    "email-src", "email-subject"
}

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class MISPEvent:
    event_id: str
    uuid: str
    info: str           # Event title/description
    threat_level: str   # 1=High, 2=Medium, 3=Low, 4=Undefined
    tlp: str
    tags: list[str]
    date: str
    org: str
    attribute_count: int


@dataclass
class NormalizedIOC:
    value: str
    ioc_type: str       # ip, domain, url, hash_md5, hash_sha256, email
    raw_type: str       # Original MISP attribute type
    event_id: str
    event_title: str
    threat_level: str
    tlp: str
    tags: list[str]
    first_seen: str
    source: str = "MISP"

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# MISP Client (wraps PyMISP with error handling)
# ---------------------------------------------------------------------------

class MISPClient:
    """
    Thin wrapper around PyMISP for feed parsing use case.
    Falls back to mock data if PyMISP is not installed (for demo/testing).
    """

    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        self.url = url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._client = None
        self._connected = False
        self._connect()

    def _connect(self):
        try:
            from pymisp import PyMISP
            self._client = PyMISP(self.url, self.api_key, self.verify_ssl)
            self._connected = True
            print(f"[+] Connected to MISP: {self.url}")
        except ImportError:
            print("[!] PyMISP not installed — running in demo mode with sample data.")
            print("    Install with: pip install pymisp")
        except Exception as e:
            print(f"[!] Could not connect to MISP ({e}) — running in demo mode.")

    def get_recent_events(self, days: int = 7) -> list[dict]:
        """Fetch events published in the last N days."""
        if not self._connected:
            return self._mock_events(days)

        try:
            since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
            events = self._client.search(
                controller="events",
                published=True,
                publish_timestamp=since,
                pythonify=True
            )
            return [e.to_dict() for e in events]
        except Exception as e:
            print(f"[!] Error fetching MISP events: {e}")
            return []

    def _mock_events(self, days: int) -> list[dict]:
        """Sample data for demo/testing without a live MISP instance."""
        return [
            {
                "id": "1001",
                "uuid": "5e4f1234-abcd-1234-abcd-000011112222",
                "info": "APT29 Phishing Campaign — Finance Sector",
                "threat_level_id": "1",
                "date": (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d"),
                "Orgc": {"name": "CERT-EU"},
                "Attribute": [
                    {"type": "ip-dst", "value": "203.0.113.42", "timestamp": "1700000000"},
                    {"type": "domain", "value": "malicious-login.xyz", "timestamp": "1700000000"},
                    {"type": "url", "value": "http://malicious-login.xyz/payload", "timestamp": "1700000000"},
                    {"type": "sha256", "value": "a" * 64, "timestamp": "1700000000"},
                    {"type": "email-src", "value": "phish@attacker.example", "timestamp": "1700000000"},
                ],
                "Tag": [{"name": "tlp:amber"}, {"name": "apt29"}, {"name": "phishing"}]
            },
            {
                "id": "1002",
                "uuid": "5e4f5678-abcd-5678-abcd-000033334444",
                "info": "Cobalt Strike C2 Infrastructure",
                "threat_level_id": "1",
                "date": (datetime.utcnow() - timedelta(days=2)).strftime("%Y-%m-%d"),
                "Orgc": {"name": "InternalSOC"},
                "Attribute": [
                    {"type": "ip-dst", "value": "198.51.100.77", "timestamp": "1700100000"},
                    {"type": "ip-dst", "value": "192.0.2.15", "timestamp": "1700100000"},
                    {"type": "domain", "value": "c2-beacon.net", "timestamp": "1700100000"},
                    {"type": "md5", "value": "b" * 32, "timestamp": "1700100000"},
                ],
                "Tag": [{"name": "tlp:red"}, {"name": "cobalt-strike"}, {"name": "c2"}]
            }
        ]


# ---------------------------------------------------------------------------
# IOC Normalization
# ---------------------------------------------------------------------------

TYPE_MAP = {
    "ip-src": "ip", "ip-dst": "ip",
    "ip-src|port": "ip", "ip-dst|port": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "url",
    "md5": "hash_md5", "sha1": "hash_sha1",
    "sha256": "hash_sha256", "sha512": "hash_sha512",
    "email-src": "email", "email-subject": "email_subject"
}

THREAT_LEVEL_MAP = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}


def extract_tlp(tags: list[dict]) -> str:
    for tag in tags:
        name = tag.get("name", "").lower()
        if name.startswith("tlp:"):
            return name.upper()
    return "TLP:WHITE"


def normalize_ioc_value(value: str, raw_type: str) -> str:
    """Strip ports from ip|port composite attributes."""
    if "|port" in raw_type:
        return value.split("|")[0]
    return value.strip().lower()


def parse_event_to_iocs(event: dict) -> tuple[MISPEvent, list[NormalizedIOC]]:
    tags = event.get("Tag", [])
    tag_names = [t.get("name", "") for t in tags]
    tlp = extract_tlp(tags)
    threat_level = THREAT_LEVEL_MAP.get(str(event.get("threat_level_id", "4")), "Undefined")

    misp_event = MISPEvent(
        event_id=str(event.get("id", "")),
        uuid=event.get("uuid", ""),
        info=event.get("info", ""),
        threat_level=threat_level,
        tlp=tlp,
        tags=tag_names,
        date=event.get("date", ""),
        org=event.get("Orgc", {}).get("name", "Unknown"),
        attribute_count=len(event.get("Attribute", []))
    )

    iocs = []
    for attr in event.get("Attribute", []):
        raw_type = attr.get("type", "")
        if raw_type not in SUPPORTED_ATTRIBUTE_TYPES:
            continue

        normalized_value = normalize_ioc_value(attr.get("value", ""), raw_type)
        if not normalized_value:
            continue

        ts = attr.get("timestamp", "")
        try:
            first_seen = datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            first_seen = misp_event.date

        iocs.append(NormalizedIOC(
            value=normalized_value,
            ioc_type=TYPE_MAP.get(raw_type, raw_type),
            raw_type=raw_type,
            event_id=misp_event.event_id,
            event_title=misp_event.info,
            threat_level=threat_level,
            tlp=tlp,
            tags=tag_names,
            first_seen=first_seen
        ))

    return misp_event, iocs


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_json(iocs: list[NormalizedIOC], output_path: str):
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": "MISP",
        "total_iocs": len(iocs),
        "iocs": [ioc.to_dict() for ioc in iocs]
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Exported {len(iocs)} IOCs to {output_path}")


def export_csv(iocs: list[NormalizedIOC], output_path: str):
    if not iocs:
        print("[!] No IOCs to export.")
        return
    fieldnames = list(asdict(iocs[0]).keys())
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ioc in iocs:
            row = ioc.to_dict()
            row["tags"] = "|".join(row["tags"])
            writer.writerow(row)
    print(f"[+] Exported {len(iocs)} IOCs to {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Pull and normalize IOCs from MISP")
    parser.add_argument("--days", type=int, default=7, help="Events from last N days (default: 7)")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--output", default="samples/misp_iocs.json")
    args = parser.parse_args()

    client = MISPClient(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)
    raw_events = client.get_recent_events(days=args.days)

    all_iocs = []
    event_count = 0
    for raw_event in raw_events:
        misp_event, iocs = parse_event_to_iocs(raw_event)
        all_iocs.extend(iocs)
        event_count += 1
        print(f"  [{misp_event.threat_level}] {misp_event.info} — {len(iocs)} IOCs")

    # Deduplicate by value+type
    seen = set()
    deduped = []
    for ioc in all_iocs:
        key = (ioc.value, ioc.ioc_type)
        if key not in seen:
            seen.add(key)
            deduped.append(ioc)

    print(f"\n[+] Processed {event_count} events — {len(all_iocs)} raw IOCs → {len(deduped)} after dedup")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    if args.format == "csv":
        export_csv(deduped, args.output)
    else:
        export_json(deduped, args.output)


if __name__ == "__main__":
    main()
