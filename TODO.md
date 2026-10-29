# TODO (OLD)

- Split up `enrichment/placeholder.py`
- Different types in `query_services`?
- Continue transferring

- get_api_key from calls to remove the keys from CONFIG.json -- possibly point to a different location
- make sample CONFIG.json

- Setup GitHub ("Begin transfer from old PrismTEC local directory")


## Finished Migrating:
- query_services
- calls
others


---

# TODO

## 10272026

- Installed project
- Verified working:
    - utils/
        - general/
            - helpers.py
            - indicators.py
            - path.py
        - api/
            - calls.py
            - query_services.py
    - enrichment/
        - enrich.py
- Verified mirgrated
    - utils/
        - general/
            - helpers.py
            - indicators.py
            - path.py
        - api/
            - calls.py
            - query_services.py

- clean up
- add `__all__`

- add whatever is simple, urls hashes domains etc
  - this would go in query_services.py with the `if indicator...`

figure out how to query services cleanly per type. possibly need to build report as well during it?

# 10282026

- finish process_iocs.py and enrich.py as well as make batch IP processing functional. 
- Need to make build_report.py
- add hash functionality