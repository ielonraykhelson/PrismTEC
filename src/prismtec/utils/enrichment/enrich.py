from prismtec.utils.api.query_services import (
    query_virustotal,
    query_shodan,
    query_abuseipdb,
    query_ipinfo
)
from prismtec.utils.enrichment.process_iocs import load_iocs

__all__ = [
    'enrich_ip',
    'enrich_hash',
    'enrich_domain'
]

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
    
    report = {ip_address: {'queried_services': [], 'errors': {}}}

    if 'virustotal' in services:
        try:
            result = query_virustotal(
                indicator=ip_address,
                indicator_type='ip'
            )
            if len(result) != 0:
                report[ip_address]['VirusTotal'] = result
                report[ip_address]['queried_services'].append('virustotal')
        except Exception as e:
            report[ip_address]['errors']['VirusTotal'] = f'{type(e).__name__}: {e}'
    if 'shodan' in services:
        report[ip_address]['errors']['Shodan'] = f'[!] SHODAN IS UNIMPLEMENTED.'
        # result = query_shodan(
        #     indicator=ip_address,
        #     indicator_type='ip'
        # )
        # if len(result) != 0:
        #     report[ip_address]['Shodan'] = result
        #     report[ip_address]['queried_services'].append('Shodan')
    if 'abuseipdb' in services:
        try:
            result = query_abuseipdb(
                indicator=ip_address,
                indicator_type='ip'
            )
            if len(result) != 0:
                report[ip_address]['AbuseIPDB'] = result
                report[ip_address]['queried_services'].append('AbuseIPDB')
        except Exception as e:
            report[ip_address]['errors']['AbuseIPDB'] = f'{type(e).__name__}: {e}'
    if 'ipinfo' in services:
        try:
            result = query_ipinfo(
                indicator=ip_address,
                fields=['ip', 'org']
            )
            if len(result) != 0:
                report[ip_address]['IPInfo'] = result
                report[ip_address]['queried_services'].append('IPInfo')
        except Exception as e:
            report[ip_address]['errors']['IPinfo'] = f'{type(e).__name__}: {e}'

    return report
    
def enrich_hash(hash: str, 
                services: list = [
                        'virustotal'
                    ]
                ) -> dict:
    if services is not None:
        services = services
    
    report = {hash: {'queried_services': [], 'errors': {}}}

    if 'virustotal' in services:
        try:
            result = query_virustotal(
                indicator=hash,
                indicator_type='hash'
            )
            if len(result) != 0:
                report[hash]['VirusTotal'] = result
                report[hash]['queried_services'].append('virustotal')
        except Exception as e:
            report[hash]['errors']['VirusTotal'] = f'{type(e).__name__}: {e}'
            
    return report

def enrich_domain(domain: str, 
                services: list = [
                        'virustotal'
                    ]
                ) -> dict:
    if services is not None:
        services = services
    
    report = {domain: {'queried_services': [], 'errors': {}}}

    try:
        if 'virustotal' in services:
            result = query_virustotal(
                indicator=domain,
                indicator_type='domain'
            )
            if len(result) != 0:
                report[domain]['VirusTotal'] = result
                report[domain]['queried_services'].append('virustotal')
    except Exception as e:
        report[domain]['errors']['VirusTotal'] = f'{type(e).__name__}: {e}'


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
