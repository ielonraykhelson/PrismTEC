
---

# PrismTEC
*Version 1.0.1*

> Threat Enrichment and Correlation Engine

PrismTEC is a Python-based CLI (Command-line Interface) tool that enriches Indicators of Compromise (IOCs) with threat intelligence APIs and consolidates results into timestamped JSON reports.

---

## Features

- Enrich IP addresses, domains, and file hashes using a combination of VirusTotal, AbuseIPDB, and IPInfo
- Process individual indicators via direct command-line entry or in batches from JSON input files
- Configure the enrichment process and generate structured JSON reports
- Easily integrate PrismTEC standardized JSON reports into other tools and platforms

#### Supported services and indicator types

| **Indicator type** | **Supported service(s)** | **Specifications** |
| --- | --- | --- |
| *IP address* | `VirusTotal`, `IPinfo`, `AbuseIPDB` | `IPv4` is supported, `IPv6` is unsupported. |
| *Hash* | `VirusTotal` | Any hashing algorithm supported by VirusTotal is supported by PrismTEC. |
| *Domain* | `VirusTotal` | Any domain format supported by VirusTotal is supported by PrismTEC. |

## Tech Stack

- Python
- REST APIs
- JSON
- Requests
- Argparse

## Installation

```
> git clone https://github.com/ielonraykhelson/PrismTEC.git
> # cd into cloned directory
> python -m pip install -e .
```

## Configuration

> NOTE: *You* **must** *configure API keys in* `src/prismtec/assets/CONFIG.json`. *You are only required to use API keys for the services you intend to use.*

> NOTE: *If you'd like execution to use the `prismtec` command directly, you must either add it to PATH or as an environment variable. Otherwise, execution will be module-based – `python -m prismtec.cli ...`.*

#### Example `CONFIG.json`:

```json
{
    "API-keys": {
        "virustotal": "YOUR_API_KEY",
        "abuseipdb": "YOUR_API_KEY",
        "ipinfo": "YOUR_API_KEY"
    }
}
```

## Usage

#### Enrich individual and multiple indicators

```shell
# Enrich an IP address
$ python -m prismtec.cli enrich -ip [ip]

# Enrich multiple IP addresses
$ python -m prismtec.cli enrich -ip 8.8.8.8 9.9.9.9

# Enrich a domain
$ python -m prismtec.cli enrich -domain [domain]

# Enrich a file hash
$ python -m prismtec.cli enrich -hash [hash]

# Enrich multiple indicators
$ python -m prismtec.cli enrich -ip 8.8.8.8 9.9.9.9 -hash [hash]
```

#### Select enrichment services

```shell
# Enrich an IP using specific providers
$ python -m prismtec.cli enrich --ip 8.8.8.8 --services virustotal abuseipdb

# Enrich an IP using the default providers
$ python -m prismtec.cli enrich --ip 8.8.8.8
```

#### Batch enrichment

> PrismTEC supports processing multiple indicators from a JSON input file.

**Example enrichment.json input file**:

```json
{
    "IOCs": {
        "IP": [
            "8.8.8.8",
            "13.90.8.20"
        ],
        "HASH": [
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "1BC8F211F3AC2347613BD296DE3B78475FDC3177E8DF645B4A90EAC27A3D08E8"
        ],
        "DOMAIN": [
            "ielonraykhelson.org",
            "chatgpt.com"
        ]
    }
    
}
```

```shell
# Process a project-relative input file
$ python -m prismtec.cli enrich --input src/prismtec/assets/enrichment.json

# Process an input file using an absolute path
$ python -m prismtec.cli enrich --input "C:\IOCS\sample.json"
```

#### Generate output reports

```shell
# Specify a custom report filename
$ python -m prismtec.cli enrich --ip 8.8.8.8 --output report.json

# Specify an output directory
$ python -m prismtec.cli enrich --domain example.com --output ./reports/domain-report.json

# Export enrichment results
$ python -m prismtec.cli enrich --hash 44d88612fea8a8f36de82e1278abb02f --output ./reports/hash-report.json
```

**Report specifications:**
- Reports contain enrichment results grouped by indicator type and are saved as UTC-timestamped JSON files in the HHMM_ddmmyy (ex. `1722_092625`) format. 
- Existing reports are preserved rather than overwritten, with the new report being generated with an incrementing `-#` suffix.
- Reports are generated in JSON by default to support cross-platform implementation of PrismTEC results.

#### CLI help

```shell
# Display available commands and options
$ python -m prismtec.cli --help

# Display enrichment-specific options
$ python -m prismtec.cli enrich --help
```

## Project Structure

```shell
src/prismtec/
├── assets/
├── cli.py
├── main.py
└── utils/
    ├── api/
    ├── enrichment/
    ├── general/
    └── report/
```

| **Component** | **Description** |
| --- | --- |
| `cli.py` | Command-line interface |
| `utils/api/` | API requests and service integrations |
| `utils/enrichment/` | IOC processing and enrichment functionality |
| `utils/general/` | Indicator validation, paths, and utilities |
| `utils/report/` | JSON report generation |

## Scope and Purpose

PrismTEC is a highly configurable Python-based tool that automates threat intelligence enrichment, a crucial step in security analysis. When a suspicious indicator is identified, such as an IP address, file hash, domain, or a URL, a Security Analyst will typically query online and private databases to determine whether this indicator is malicious or benign, targeted, novel, or well-known. By doing so, an individual indicator can suggest ties to a larger malware family or attack pattern, which provides significant insight for the analyst; however, querying individual services can be cumbersome, especially when it is not a single indicator but hundreds.

To address this, PrismTEC reads either specific indicators or a batch of indicators from a single JSON file, queries various services, such as VirusTotal, AbuseIPDB, and IPinfo, through their REST APIs, and writes the combined threat intelligence findings to a single standardized JSON file. Currently, only enrichment for IP addresses, hashes, and domains is supported. 

PrismTEC was built over the course of about three months, with a month for initial planning and documentation review, using only core Python libraries and API calls, validated with repeated test runs.