"""
ioc_enrichment_pipeline.py
===========================
Combines IOCs from MISP and OTX feed parsers, deduplicates across sources,
enriches each IOC via VirusTotal, and outputs a prioritized enrichment report
in JSON and CSV formats.

Designed to run as a daily automated pipeline or be triggered by a SOAR playbook.

Usage:
    python ioc_enrichment_pipeline.py --misp-file samples/misp_iocs.json \
                                       --otx-file samples/otx_iocs.json \
                                       --output samples/enriched_iocs.json

Author: Apurva Tiwari
"""

import argparse
import csv
import json
import os
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_VT_API_KEY_HERE")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Rate limit: VT free tier = 4 requests/min
VT_RATE_LIMIT_DELAY = 15   # seconds between requests on free tier
VT_PAID_TIER = os.getenv("VT_PAID_TIER", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class EnrichedIOC:
    value: str
    ioc_type: str
    sources: list[str]
    source_events: list[str]
    adversary: str
    malware_family: str
    tlp: str
    tags: list[str]
    # VT enrichment fields
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_total_engines: int = 0
    vt_last_analysis: str = ""
    vt_tags: list = None
    # Computed fields
    risk_score: float = 0.0
    verdict: str = "UNKNOWN"
    first_seen: str = ""
    enriched_at: str = ""

    def __post_init__(self):
        if self.vt_tags is None:
            self.vt_tags = []

    def to_dict(self) -> dict:
        d = asdict(self)
        for list_field in ["sources", "source_events", "tags", "vt_tags"]:
            if isinstance(d[list_field], list):
                d[list_field] = "|".join(str(x) for x in d[list_field])
        return d


# ---------------------------------------------------------------------------
# IOC Loader — reads output from misp_feed_parser and otx_feed_parser
# ---------------------------------------------------------------------------

def load_iocs_from_file(filepath: str) -> list[dict]:
    """Load IOC JSON output from MISP or OTX feed parser."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath} — skipping")
        return []
    with open(filepath) as f:
        data = json.load(f)
    iocs = data.get("iocs", [])
    source = data.get("source", "Unknown")
    print(f"[+] Loaded {len(iocs)} IOCs from {source} ({filepath})")
    return iocs


def merge_and_deduplicate(ioc_lists: list[list[dict]]) -> list[dict]:
    """
    Merge IOCs from multiple sources, deduplicating by (value, ioc_type).
    Merges source metadata when the same IOC appears in multiple feeds.
    """
    merged: dict[tuple, dict] = {}

    for ioc_list in ioc_lists:
        for ioc in ioc_list:
            key = (ioc["value"].lower().strip(), ioc["ioc_type"])
            if key not in merged:
                merged[key] = ioc.copy()
                merged[key]["sources"] = [ioc.get("source", "Unknown")]
                merged[key]["source_events"] = [
                    ioc.get("event_title") or ioc.get("pulse_name", "")
                ]
            else:
                # Merge sources
                existing = merged[key]
                src = ioc.get("source", "Unknown")
                if src not in existing.get("sources", []):
                    existing.setdefault("sources", []).append(src)
                event = ioc.get("event_title") or ioc.get("pulse_name", "")
                if event and event not in existing.get("source_events", []):
                    existing.setdefault("source_events", []).append(event)

    result = list(merged.values())
    print(f"[+] Merged to {len(result)} unique IOCs after deduplication")
    return result


# ---------------------------------------------------------------------------
# VirusTotal Enrichment
# ---------------------------------------------------------------------------

class VTEnricher:

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
                "x-apikey": self.api_key,
                "Accept": "application/json"
            })
            self._connected = True
        except ImportError:
            print("[!] requests not installed — VT enrichment will use mock data")

    def _endpoint_for_type(self, ioc_type: str, value: str) -> Optional[str]:
        if ioc_type == "ip":
            return f"{VT_BASE_URL}/ip_addresses/{value}"
        elif ioc_type == "domain":
            return f"{VT_BASE_URL}/domains/{value}"
        elif ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            return f"{VT_BASE_URL}/urls/{url_id}"
        elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
            return f"{VT_BASE_URL}/files/{value}"
        return None

    def enrich(self, ioc_value: str, ioc_type: str) -> dict:
        """Returns VT enrichment dict for a single IOC."""
        if not self._connected or self.api_key == "YOUR_VT_API_KEY_HERE":
            return self._mock_result(ioc_value, ioc_type)

        endpoint = self._endpoint_for_type(ioc_type, ioc_value)
        if not endpoint:
            return {"error": f"Unsupported type: {ioc_type}"}

        try:
            resp = self._session.get(endpoint, timeout=15)
            if resp.status_code == 404:
                return {"malicious": 0, "suspicious": 0, "total": 0, "not_found": True}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
                "last_analysis": data.get("last_analysis_date", ""),
                "tags": data.get("tags", [])
            }
        except Exception as e:
            return {"error": str(e)}

    def _mock_result(self, value: str, ioc_type: str) -> dict:
        """Deterministic mock based on value hash for demo consistency."""
        score = sum(ord(c) for c in value) % 20
        return {
            "malicious": score,
            "suspicious": max(0, score // 3),
            "total": 72,
            "last_analysis": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tags": ["mock-data"]
        }


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

def compute_verdict(vt_malicious: int, vt_total: int, source_count: int) -> tuple[float, str]:
    if vt_total == 0:
        base_score = 20.0 if source_count > 1 else 10.0
    else:
        ratio = vt_malicious / vt_total
        if vt_malicious == 0:
            base_score = 0.0
        elif vt_malicious <= 2:
            base_score = 30.0
        elif vt_malicious <= 5:
            base_score = 55.0
        else:
            base_score = min(50.0 + ratio * 100, 100.0)

    # Boost score if seen across multiple intel sources
    source_bonus = min((source_count - 1) * 10, 20)
    final = min(round(base_score + source_bonus, 1), 100.0)

    if final >= 70:
        verdict = "MALICIOUS"
    elif final >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return final, verdict


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    misp_file: Optional[str],
    otx_file: Optional[str],
    output_path: str,
    limit: Optional[int] = None
):
    # Load
    ioc_lists = []
    if misp_file:
        ioc_lists.append(load_iocs_from_file(misp_file))
    if otx_file:
        ioc_lists.append(load_iocs_from_file(otx_file))

    if not ioc_lists:
        print("[!] No input files provided. Use --misp-file and/or --otx-file")
        return

    merged = merge_and_deduplicate(ioc_lists)
    if limit:
        merged = merged[:limit]
        print(f"[+] Processing first {limit} IOCs (--limit applied)")

    # Enrich
    enricher = VTEnricher(VT_API_KEY)
    enriched_iocs = []
    total = len(merged)

    print(f"\n[+] Enriching {total} IOCs via VirusTotal...")
    for i, ioc in enumerate(merged, 1):
        vt = enricher.enrich(ioc["value"], ioc["ioc_type"])

        vt_malicious = vt.get("malicious", 0)
        vt_total = vt.get("total", 0)
        sources = ioc.get("sources", [ioc.get("source", "Unknown")])
        risk_score, verdict = compute_verdict(vt_malicious, vt_total, len(sources))

        enriched = EnrichedIOC(
            value=ioc["value"],
            ioc_type=ioc["ioc_type"],
            sources=sources if isinstance(sources, list) else [sources],
            source_events=ioc.get("source_events", []),
            adversary=ioc.get("adversary", ""),
            malware_family=ioc.get("malware_family", ""),
            tlp=ioc.get("tlp", "TLP:WHITE"),
            tags=ioc.get("tags", []) if isinstance(ioc.get("tags"), list) else ioc.get("tags", "").split("|"),
            vt_malicious=vt_malicious,
            vt_suspicious=vt.get("suspicious", 0),
            vt_total_engines=vt_total,
            vt_last_analysis=str(vt.get("last_analysis", "")),
            vt_tags=vt.get("tags", []),
            risk_score=risk_score,
            verdict=verdict,
            first_seen=ioc.get("first_seen", ""),
            enriched_at=datetime.utcnow().isoformat() + "Z"
        )
        enriched_iocs.append(enriched)

        status = f"  [{i:>4}/{total}] {verdict:<10} score={risk_score:>5} | {ioc['value'][:50]}"
        print(status)

        # Rate limiting
        if not VT_PAID_TIER and i % 4 == 0 and i < total:
            print(f"  [~] Rate limit pause ({VT_RATE_LIMIT_DELAY}s)...")
            time.sleep(VT_RATE_LIMIT_DELAY)

    # Sort by risk score descending
    enriched_iocs.sort(key=lambda x: x.risk_score, reverse=True)

    # Summary
    malicious_count = sum(1 for i in enriched_iocs if i.verdict == "MALICIOUS")
    suspicious_count = sum(1 for i in enriched_iocs if i.verdict == "SUSPICIOUS")
    print(f"\n[+] Results: {malicious_count} MALICIOUS | {suspicious_count} SUSPICIOUS | {total - malicious_count - suspicious_count} CLEAN")

    # Export JSON
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    export_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total": total,
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "clean": total - malicious_count - suspicious_count
        },
        "iocs": [asdict(ioc) for ioc in enriched_iocs]
    }
    with open(output_path, "w") as f:
        json.dump(export_data, f, indent=2)
    print(f"[+] Enriched report → {output_path}")

    # Export CSV alongside
    csv_path = output_path.replace(".json", ".csv")
    with open(csv_path, "w", newline="") as f:
        if enriched_iocs:
            writer = csv.DictWriter(f, fieldnames=list(enriched_iocs[0].to_dict().keys()))
            writer.writeheader()
            writer.writerows([ioc.to_dict() for ioc in enriched_iocs])
    print(f"[+] CSV report → {csv_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="IOC enrichment pipeline — MISP + OTX → VirusTotal")
    parser.add_argument("--misp-file", default="samples/misp_iocs.json")
    parser.add_argument("--otx-file", default="samples/otx_iocs.json")
    parser.add_argument("--output", default="samples/enriched_iocs.json")
    parser.add_argument("--limit", type=int, default=None, help="Process only first N IOCs (for testing)")
    args = parser.parse_args()

    run_pipeline(args.misp_file, args.otx_file, args.output, args.limit)


if __name__ == "__main__":
    main()
