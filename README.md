# PrismTEC
PrismTEC: The Prism Threat Enrichment and Correlation engine ingests alerts, normalizes it into a standardized format, enriches any IOCs with threat intelligence, calculates risk and confidence scores, and exports the enriched IOC information as formatted JSON generalized to support platform-ambiguity.

---

## Operational Layers

**Layer 1: Data Ingestion and Normalization**
- Ingest bulk or isolated threat data (from "predictable structured data")
  - Supported formats:
    - `Splunk`, `XSOAR`
- Reformat ingested data to PrismTEC JSON-Struct



---

## Sources for Threat Intelligence Enrichment

| ***Intelligence Focus Area*** | ***Source*** |
| --- | --- |
| **IPv4 Address** | `AbuseIPDB`, `VirusTotal`, `Shodan` |
| **Domain** | `VirusTotal`, `Whois` |
| **URL** | `VirusTotal`, `URLScan` |

IP:
- Reputation (is this bad):
  - VirusTotal/AbuseIPDB
- Infrastructure (what is it):
  - ipinfo
- Exposure (what is it doing):
  - Shodan
- DNS Relationships (what is it connected to?)
  - SecurityTrails
- Context (why does it matter):
  - GreyNoise (noise vs threat classification)
  - OTX (campaign context)

#edit

---

## Setup Instructions:
- Clone this repo
- Navigate to `/PrismTEC/` (where the `pyproject.toml` is located)
  - Install modules and fix PATH:
    - `pip install -e .`
- Add your API keys to `./CONFIG.json`

---

## Relevant Notes:

### Services

**VirusTotal**:
- [IP-Object Return Value](https://docs.virustotal.com/reference/ip-object)
- [VT API Docs](https://docs.virustotal.com/reference/ip-info)

**AbuseIPDB**:
- [AbuseIPDB Documentation](https://docs.abuseipdb.com/?python#introduction)
- AbuseIPDB documentation states the following:
  - Too many requests result in `HTTP:429 - Too Many Requests`
  - [API Daily Rate Limits](https://docs.abuseipdb.com/?python#api-daily-rate-limits)
  - All API keys should be passed via headers, though they can be passed via parameters as well.

**IpInfo**:
- [IpInfo Docs](https://ipinfo.io/developers/lite-api)
  - No daily or monthly limit and provides unlimited access
  - ***Available fields listed in docs***
  - `/me` in the url is to get information about your own IP

**Shodan**:
- [Shodan Dashboard](https://www.shodan.io/dashboard)
- [Shodan Documentation](https://shodan.readthedocs.io/en/latest/)
  - [Shodan Documentation / Looking up a host](https://shodan.readthedocs.io/en/latest/tutorial.html#looking-up-a-host)
  - [Shodan Documentation / Functions and Exceptions](https://shodan.readthedocs.io/en/latest/api.html)

### Other

**IPaddress**:
- [IPaddress Docs](https://docs.python.org/3/library/ipaddress.html)

**JSON API Specifications**:
- [JSON API specs](https://jsonapi.org/format/#errors)