# Release Notes

---

## PrismTEC v1.0.1, 11/04/2026

**Bug fixes:**
- `calls.py`
    - An API timeout or hanging request would terminate or freeze execution, making it a single-point-of-failure. Integrating API request timeouts should address this...
    - Fixed a pathing bug in `get_api_key()`
- `enrich.py`
    - API errors would terminate execution, making it an SPOF. Integrating query error-handling should address this...

**Changes:**
- `pyproject.toml`
    - Added required dependencies to project setup.
    - Updated version number.
- Report generation
    - Added an `errors` field to gracefully handle API errors during enrichment processing, if they occur.
- API calls
    - Added a 15 second timeout to the VirusTotal and AbuseIPDB IOC enrichment calls to address API errors and hanging responses.
    - HTTP errors are handled and passed into the `errors` field of the generated report.

**Documentation:**
- `README.md`
    - PrismTEC could not be ran via CLI unless added to PATH. Rather than deal with environment variables, I am listing the example execution to be done through module-based execution. For example, `python -m prismtec.cli enrich ...`.
    - However, if the `prismtec` command is added to PATH, execution would simply be `prismtec ...`.

**Additions:**
- `CHANGELOG.md`

## PrismTEC v1.0.0 - Official Release, 11/02/2026

Official release!

---