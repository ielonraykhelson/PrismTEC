from prismtec.utils.general.path import get_assets_path, validate_path, append_to_assets_path

__all__ = [
    '',
]

# locate iocs.json
def locate_iocs(file_path: str = 'TARGET.json') -> bool:
    # can specify, but default to 'TARGET.json'
    
    #target_path = f'{get_assets_path()}\\{file_path}'
    # ^ commenting, only use if just using locate_iocs() itself
    
    if validate_path(path=file_path): # file located
        return True
    else:
        print(f'[!] CANNOT LOCATE TARGET IOCs AT: `{file_path}`.')
        return False
        
# load data, for thing in type, query these services this way.
def load_data(file_path: str = 'TARGET.json') -> dict:
    # returns the base dict. use load_iocs() to load iocs fully
    import json
    
    file_path = append_to_assets_path(path=file_path)
    
    if locate_iocs(file_path=file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
            return data
    else:
        print(f'[!] Error loading data with load_data() at path `{file_path}`. Returning an empty dictionary.')
        return {}
        
def load_iocs(file_path: str = 'TARGET.json') -> dict:
    # returns iocs. use load_data() to load just data
    data = load_data(file_path=file_path)
    
    if 'IOCs' not in data:
        print(f'[!] IOCs not in data at load_iocs()\n- {data}')
        return {}
    
    iocs = data['IOCs']
    return iocs

def process_iocs(data: dict) -> None:
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
    from prismtec.utils.enrichment.enrich import(
        enrich_ip,
        enrich_hash,
        enrich_domain
    )
    
    report = {
        'IP': [],
        'HASH': [],
        'DOMAIN': []
    }
    
    for category in data.keys():
        for indicator in data[category]:
            if category == 'IP':
                print(f'({category}) {indicator}')
                print('\tEnriching IP ... ', end='')
                report['IP'].append(enrich_ip(
                    ip_address=indicator,
                    services=[
                        'virustotal',
                        'abuseipdb',
                        'ipinfo'
                    ]
                ))
                print('DONE')
            elif category == 'HASH':
                print(f'({category}) {indicator}')
                print('\tEnriching HASH ... ', end='')
                report['HASH'].append(enrich_hash(
                    hash=indicator,
                    services=[
                        'virustotal'
                    ]
                ))
                print('DONE')
            elif category == 'DOMAIN':
                print(f'({category}) {indicator}')
                print('\tEnriching DOMAIN ... ', end='')
                report['DOMAIN'].append(enrich_domain(
                    domain=indicator,
                    services=[
                        'virustotal'
                    ]
                ))
                print('DONE')
            else:
                import warnings
                warnings.warn(
                    f'ERROR in process_iocs:\n'
                    f'- Unknown category ({category}) in data.\n'
                    f'data[{category}]:\n'
                    f'---\n{data[category]}\n'
                    f'---\n',
                    UserWarning
                )
                pass
            
    return report

if __name__ == '__main__':
    print('process_iocs.py module loaded.')
    # TESTING FUNCTIONALITY
    # path = 'TARGET.json'
    # iocs = load_iocs(file_path=path)
    # for category in iocs.keys():
    #     for indicator in iocs[category]:
    #         print(f'({category}) {indicator}')
    
    # ---
    # from prismtec.utils.report.generation import generate_report
    # iocs = {
    #     "IP": [
    #         "8.8.8.8",
    #         "13.90.8.20"
    #     ],
    #     "HASH": [
    #         "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    #         "1BC8F211F3AC2347613BD296DE3B78475FDC3177E8DF645B4A90EAC27A3D08E8"
    #     ],
    #     "DOMAIN": [
    #         "ielonraykhelson.org",
    #         "chatgpt.com"
    #     ],
    #     "TEST": [
    #         "TEST_IOC_A",
    #         "TEST_IOC_B"
    #     ]
    # }
    # generate_report(
    #     data=process_iocs(data=iocs),
    #     file_path='test',
    #     extension='.json'
    # )
    # print('\n=============\nDONE')