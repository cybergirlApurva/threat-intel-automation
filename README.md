# threat-intel-automation

Python pipeline for automated threat intelligence collection, IOC normalization, multi-source enrichment, and prioritized reporting. Pulls from **MISP** and **AlienVault OTX**, enriches via **VirusTotal**, and outputs analyst-ready JSON/CSV reports.

All scripts run in demo mode without API keys — mock data is included so you can see the output format immediately.

---

## What It Does

```
MISP  ──┐
         ├──▶ merge + deduplicate ──▶ VirusTotal enrichment ──▶ risk scoring ──▶ JSON/CSV report
OTX   ──┘
```

1. **`misp_feed_parser.py`** — connects to MISP, pulls recent threat events, extracts and normalizes IOCs (IP, domain, URL, hash, email)
2. **`otx_feed_parser.py`** — pulls subscribed OTX pulses, extracts IOC indicators with adversary and malware family metadata
3. **`ioc_enrichment_pipeline.py`** — merges both feeds, deduplicates, enriches each IOC via VirusTotal, computes a weighted risk score, and outputs a prioritized report

---

## Quick Start

```bash
# Clone and install dependencies
git clone https://github.com/cybergirlApurva/threat-intel-automation.git
cd threat-intel-automation
pip install -r requirements.txt

# Run in demo mode (no API keys needed — uses built-in mock data)
python src/misp_feed_parser.py --days 7 --output samples/misp_iocs.json
python src/otx_feed_parser.py --days 7 --output samples/otx_iocs.json
python src/ioc_enrichment_pipeline.py \
    --misp-file samples/misp_iocs.json \
    --otx-file samples/otx_iocs.json \
    --output samples/enriched_iocs.json
```

---

## Configuration

Set API keys as environment variables — never hardcode credentials:

```bash
export MISP_URL="https://your-misp-instance.com"
export MISP_API_KEY="your_misp_api_key"
export OTX_API_KEY="your_otx_api_key"
export VT_API_KEY="your_virustotal_api_key"

# Optional: set to true if you have a paid VT tier (removes rate limiting)
export VT_PAID_TIER="false"
```

---

## Sample Output

Running the full pipeline produces a prioritized enrichment report:

```
[+] Loaded 12 IOCs from MISP (samples/misp_iocs.json)
[+] Loaded 10 IOCs from AlienVault OTX (samples/otx_iocs.json)
[+] Merged to 18 unique IOCs after deduplication

[+] Enriching 18 IOCs via VirusTotal...
  [  1/18] MALICIOUS   score= 95.0 | 198.51.100.23
  [  2/18] MALICIOUS   score= 87.3 | 203.0.113.42
  [  3/18] MALICIOUS   score= 78.5 | malicious-login.xyz
  [  4/18] SUSPICIOUS  score= 48.0 | 192.0.2.44
  ...

[+] Results: 4 MALICIOUS | 2 SUSPICIOUS | 12 CLEAN
[+] Enriched report → samples/enriched_iocs.json
[+] CSV report     → samples/enriched_iocs.csv
```

See [`samples/enriched_iocs_sample.json`](samples/enriched_iocs_sample.json) for full output format.

---

## Risk Scoring

Each IOC receives a 0–100 risk score computed from:

| Source | Weight | Signal |
|--------|--------|--------|
| VirusTotal engine ratio | 55% | Primary malicious verdict signal |
| Multi-source presence | 20% | Same IOC in MISP + OTX = higher confidence |
| VT malicious count | 25% | Raw engine count threshold |

| Score | Verdict |
|-------|---------|
| 70–100 | MALICIOUS |
| 30–69 | SUSPICIOUS |
| 0–29 | CLEAN |

---

## Repository Structure

```
threat-intel-automation/
├── src/
│   ├── misp_feed_parser.py          # MISP event → normalized IOC extractor
│   ├── otx_feed_parser.py           # OTX pulse → normalized IOC extractor
│   └── ioc_enrichment_pipeline.py   # Merge + VT enrichment + risk scoring
├── samples/
│   └── enriched_iocs_sample.json    # Example pipeline output
├── requirements.txt
└── README.md
```

---


## Sample Output

### Pipeline Run — MISP + OTX Feed Parsing
![Pipeline Output](screenshots/Screenshot%202026-07-09%20at%208.22.27%E2%80%AFPM.png)

## Integration Points

This pipeline is designed to feed into downstream security tooling:

- **SOAR** — Output JSON consumed by `ioc-enrichment-playbook` in [`soar-playbooks`](https://github.com/cybergirlApurva/soar-playbooks)
- **SIEM** — Enriched IOC list can be used to build watchlists in Azure Sentinel
- **Firewall** — MALICIOUS-verdict IOCs can be bulk-pushed to Palo Alto block lists via API
- **Kibana** — JSON output maps directly to Kibana index for IOC dashboard visualization

---

## Rate Limits

| API | Free Tier | Paid Tier |
|-----|-----------|-----------|
| VirusTotal | 4 req/min | 1000+ req/min |
| OTX | 10,000 req/day | — |
| MISP | No limit (self-hosted) | — |

The pipeline auto-pauses for VT free tier. Set `VT_PAID_TIER=true` to disable the delay.

---

## Related Projects

- [`soar-playbooks`](https://github.com/cybergirlApurva/soar-playbooks) — FortiSOAR playbooks that consume this pipeline's output
- [`siem-detection-rules`](https://github.com/cybergirlApurva/siem-detection-rules) — KQL rules that can be seeded with IOCs from this pipeline

---

*Apurva Tiwari · [LinkedIn](https://linkedin.com/in/apurva-tiwari) · MS Cybersecurity, George Washington University*
