from prismtec.utils.api.query_services import (
    query_virustotal,
    query_shodan,
    query_abuseipdb,
    query_ipinfo
)
from prismtec.utils.enrichment.process_iocs import load_iocs

def enrich_ip(ip_address: str, 
              services: list = [
                    'virustotal',
                    'abuseipdb',
                    'ipinfo'
                  ]
              ) -> dict:
    # TODO: shodan is unfunctional
    # TODO: Add an argument `ipinfo_fields`
    if services is not None:
        services = services
    
    report = {ip_address: {'queried_services': []}}

    if 'virustotal' in services:
        result = query_virustotal(
            indicator=ip_address,
            indicator_type='ip'
        )
        if len(result) != 0:
            report[ip_address]['VirusTotal'] = result
            report[ip_address]['queried_services'].append('virustotal')

    if 'shodan' in services:
        result = query_shodan(
            indicator=ip_address,
            indicator_type='ip'
        )
        if len(result) != 0:
            report[ip_address]['Shodan'] = result
            report[ip_address]['queried_services'].append('Shodan')

    if 'abuseipdb' in services:
        result = query_abuseipdb(
            indicator=ip_address,
            indicator_type='ip'
        )
        if len(result) != 0:
            report[ip_address]['AbuseIPDB'] = result
            report[ip_address]['queried_services'].append('AbuseIPDB')

    if 'ipinfo' in services:
        result = query_ipinfo(
            indicator=ip_address,
            fields=['ip', 'org']
        )
        if len(result) != 0:
            report[ip_address]['IPInfo'] = result
            report[ip_address]['queried_services'].append('IPInfo')

    return report
    
def enrich_hash(hash: str, 
                services: list = [
                        'virustotal'
                    ]
                ) -> dict:
    if services is not None:
        services = services
    
    report = {hash: {'queried_services': []}}

    if 'virustotal' in services:
        result = query_virustotal(
            indicator=hash,
            indicator_type='hash'
        )
        if len(result) != 0:
            report[hash]['VirusTotal'] = result
            report[hash]['queried_services'].append('virustotal')
            
    return report

def enrich_domain(domain: str, 
                services: list = [
                        'virustotal'
                    ]
                ) -> dict:
    if services is not None:
        services = services
    
    report = {domain: {'queried_services': []}}

    if 'virustotal' in services:
        result = query_virustotal(
            indicator=domain,
            indicator_type='domain'
        )
        if len(result) != 0:
            report[domain]['VirusTotal'] = result
            report[domain]['queried_services'].append('virustotal')
            
    return report

if __name__ == '__main__':
    print('enrich.py module loaded.')
    # TESTING FUNCTIONALITY
    # path = 'TARGET.json'
    # iocs = load_iocs(file_path=path)
    # for category in iocs.keys():
    #     for indicator in iocs[category]:
    #         print(f'({category}) {indicator}')
    #         if category == 'DOMAIN':
    #             report = enrich_domain(
    #                 domain=indicator,
    #                 services=['virustotal']
    #             )
    #             print(f'\n---\n{report}\n---\n')
