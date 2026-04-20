"""
otx_feed_parser.py
==================
Pulls threat intelligence pulses from AlienVault OTX, extracts IOCs,
and exports normalized output to JSON or CSV for downstream enrichment.

Supports both subscribed pulses (your feed) and direct pulse lookup by ID.

Usage:
    python otx_feed_parser.py --days 3 --output samples/otx_iocs.json
    python otx_feed_parser.py --pulse-id <PULSE_ID> --format csv

Author: Apurva Tiwari
"""

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OTX_API_KEY = os.getenv("OTX_API_KEY", "YOUR_OTX_API_KEY_HERE")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# OTX indicator types to extract
SUPPORTED_OTX_TYPES = {
    "IPv4", "IPv6", "domain", "hostname",
    "URL", "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256",
    "email", "CIDR"
}

OTX_TYPE_MAP = {
    "IPv4": "ip", "IPv6": "ip", "CIDR": "ip_cidr",
    "domain": "domain", "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "hash_md5",
    "FileHash-SHA1": "hash_sha1",
    "FileHash-SHA256": "hash_sha256",
    "email": "email"
}

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class OTXPulse:
    pulse_id: str
    name: str
    description: str
    author: str
    tlp: str
    tags: list[str]
    malware_families: list[str]
    adversary: str
    created: str
    modified: str
    indicator_count: int


@dataclass
class NormalizedIOC:
    value: str
    ioc_type: str
    pulse_id: str
    pulse_name: str
    adversary: str
    malware_family: str
    tlp: str
    tags: list[str]
    created: str
    source: str = "AlienVault OTX"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["tags"] = "|".join(d["tags"]) if isinstance(d["tags"], list) else d["tags"]
        return d


# ---------------------------------------------------------------------------
# OTX Client
# ---------------------------------------------------------------------------

class OTXClient:
    """
    Wrapper around OTX REST API.
    Falls back to mock data if OTXv2 SDK or requests is not available.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._session = None
        self._connected = False
        self._connect()

    def _connect(self):
        try:
            import requests
            self._session = requests.Session()
            self._session.headers.update({
                "X-OTX-API-KEY": self.api_key,
                "Content-Type": "application/json"
            })
            self._connected = True
            print(f"[+] OTX client initialized")
        except ImportError:
            print("[!] requests not installed — running in demo mode.")
            print("    Install with: pip install requests")

    def get_subscribed_pulses(self, days: int = 7) -> list[dict]:
        """Fetch pulses from your OTX subscriptions modified in last N days."""
        if not self._connected:
            return self._mock_pulses()

        try:
            since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            )
            url = f"{OTX_BASE_URL}/pulses/subscribed"
            params = {"modified_since": since, "limit": 100}
            pulses = []
            while url:
                resp = self._session.get(url, params=params, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                pulses.extend(data.get("results", []))
                url = data.get("next")
                params = {}
            return pulses
        except Exception as e:
            print(f"[!] Error fetching OTX pulses: {e}")
            return []

    def get_pulse_by_id(self, pulse_id: str) -> Optional[dict]:
        """Fetch a specific pulse by ID."""
        if not self._connected:
            return self._mock_pulses()[0]
        try:
            url = f"{OTX_BASE_URL}/pulses/{pulse_id}"
            resp = self._session.get(url, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"[!] Error fetching pulse {pulse_id}: {e}")
            return None

    def _mock_pulses(self) -> list[dict]:
        return [
            {
                "id": "abc123def456",
                "name": "LockBit 3.0 Ransomware IOCs — Q4 2024",
                "description": "C2 infrastructure and file hashes associated with LockBit 3.0 campaigns",
                "author_name": "AlienVault",
                "TLP": "white",
                "tags": ["ransomware", "lockbit", "c2", "finance-sector"],
                "malware_families": [{"display_name": "LockBit"}],
                "adversary": "LockBit Group",
                "created": "2024-10-15T08:00:00.000Z",
                "modified": "2024-10-16T12:00:00.000Z",
                "indicators": [
                    {"type": "IPv4", "indicator": "198.51.100.23", "created": "2024-10-15T08:00:00Z"},
                    {"type": "IPv4", "indicator": "203.0.113.99", "created": "2024-10-15T08:00:00Z"},
                    {"type": "domain", "indicator": "lockbit-leak.onion.example", "created": "2024-10-15T08:00:00Z"},
                    {"type": "FileHash-SHA256", "indicator": "c" * 64, "created": "2024-10-15T08:00:00Z"},
                    {"type": "FileHash-MD5", "indicator": "d" * 32, "created": "2024-10-15T08:00:00Z"},
                    {"type": "URL", "indicator": "http://198.51.100.23/gate.php", "created": "2024-10-15T08:00:00Z"},
                ]
            },
            {
                "id": "xyz789uvw012",
                "name": "Emotet Botnet C2 IPs — Wave 9",
                "description": "Active Emotet C2 infrastructure observed in spam campaigns",
                "author_name": "abuse.ch",
                "TLP": "white",
                "tags": ["emotet", "botnet", "spam", "c2"],
                "malware_families": [{"display_name": "Emotet"}],
                "adversary": "",
                "created": "2024-10-17T06:00:00.000Z",
                "modified": "2024-10-17T06:00:00.000Z",
                "indicators": [
                    {"type": "IPv4", "indicator": "192.0.2.44", "created": "2024-10-17T06:00:00Z"},
                    {"type": "IPv4", "indicator": "198.51.100.55", "created": "2024-10-17T06:00:00Z"},
                    {"type": "domain", "indicator": "emotet-c2-wave9.example", "created": "2024-10-17T06:00:00Z"},
                    {"type": "FileHash-SHA256", "indicator": "e" * 64, "created": "2024-10-17T06:00:00Z"},
                ]
            }
        ]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_pulse_to_iocs(pulse: dict) -> tuple[OTXPulse, list[NormalizedIOC]]:
    malware_families = [
        m.get("display_name", "") for m in pulse.get("malware_families", [])
    ]
    tags = pulse.get("tags", [])

    otx_pulse = OTXPulse(
        pulse_id=pulse.get("id", ""),
        name=pulse.get("name", ""),
        description=pulse.get("description", ""),
        author=pulse.get("author_name", "Unknown"),
        tlp=f"TLP:{pulse.get('TLP', 'WHITE').upper()}",
        tags=tags,
        malware_families=malware_families,
        adversary=pulse.get("adversary", ""),
        created=pulse.get("created", ""),
        modified=pulse.get("modified", ""),
        indicator_count=len(pulse.get("indicators", []))
    )

    iocs = []
    for indicator in pulse.get("indicators", []):
        ioc_type_raw = indicator.get("type", "")
        if ioc_type_raw not in SUPPORTED_OTX_TYPES:
            continue

        value = indicator.get("indicator", "").strip().lower()
        if not value:
            continue

        iocs.append(NormalizedIOC(
            value=value,
            ioc_type=OTX_TYPE_MAP.get(ioc_type_raw, ioc_type_raw.lower()),
            pulse_id=otx_pulse.pulse_id,
            pulse_name=otx_pulse.name,
            adversary=otx_pulse.adversary,
            malware_family=malware_families[0] if malware_families else "",
            tlp=otx_pulse.tlp,
            tags=tags,
            created=indicator.get("created", otx_pulse.created)
        ))

    return otx_pulse, iocs


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_json(iocs: list[NormalizedIOC], output_path: str):
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": "AlienVault OTX",
        "total_iocs": len(iocs),
        "iocs": [ioc.to_dict() for ioc in iocs]
    }
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Exported {len(iocs)} IOCs → {output_path}")


def export_csv(iocs: list[NormalizedIOC], output_path: str):
    if not iocs:
        return
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(iocs[0].to_dict().keys()))
        writer.writeheader()
        writer.writerows([ioc.to_dict() for ioc in iocs])
    print(f"[+] Exported {len(iocs)} IOCs → {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Pull IOCs from AlienVault OTX")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--pulse-id", type=str, default=None)
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--output", default="samples/otx_iocs.json")
    args = parser.parse_args()

    client = OTXClient(OTX_API_KEY)

    if args.pulse_id:
        raw_pulses = [client.get_pulse_by_id(args.pulse_id)]
        raw_pulses = [p for p in raw_pulses if p]
    else:
        raw_pulses = client.get_subscribed_pulses(days=args.days)

    all_iocs = []
    for pulse in raw_pulses:
        otx_pulse, iocs = parse_pulse_to_iocs(pulse)
        all_iocs.extend(iocs)
        print(f"  [{otx_pulse.adversary or 'Unknown'}] {otx_pulse.name} — {len(iocs)} IOCs")

    # Deduplicate
    seen = set()
    deduped = [
        ioc for ioc in all_iocs
        if (ioc.value, ioc.ioc_type) not in seen
        and not seen.add((ioc.value, ioc.ioc_type))
    ]

    print(f"\n[+] {len(raw_pulses)} pulses → {len(all_iocs)} raw IOCs → {len(deduped)} after dedup")

    if args.format == "csv":
        export_csv(deduped, args.output)
    else:
        export_json(deduped, args.output)


if __name__ == "__main__":
    main()
