from prismtec.utils.general.helpers import clean
from prismtec.utils.general.indicators import is_ip
from prismtec.utils.api.calls import build_url, get_api_key, query

__all__ = [
    'query_virustotal',
    'query_shodan',
    'query_abuseipdb',
    'query_ipinfo'
]

def query_virustotal(indicator: None, indicator_type: str='ip') -> str:
    """`query_virustotal`: Queries VirusTotal for IP information.

    Args:
        indicator (None): The indicator to be queried upon.
        indicator_type (str, optional): The type of indicator(ip, hash, domain). Defaults to 'ip'.

    Raises:
        ValueError: Returns if passed indicator is invalid.

    Returns:
        dict: Dictionary of host information.
        
    Example:
    ```
    x = query_virustotal(
        indicator='33.31.58.46'
    )
    print(x)
    ```
    """
    import requests
    indicator_type = clean(indicator_type)
    
    BASE_URL = None
    HEADERS = None
    PARAMETERS = None
    
    if indicator_type == 'ip':
        if not is_ip(indicator):
            raise ValueError(f'Indicator({type(indicator)}) `{indicator}` not a valid IPaddress.')
        
        BASE_URL = 'https://www.virustotal.com/api/v3/ip_addresses'
        INDICATOR = indicator
        URL = build_url(base_url=BASE_URL,
                        params=[
                            INDICATOR
                        ])
        HEADERS = {
            'accept': 'application/json',
            'x-apikey': get_api_key('VirusTotal')
        }
    elif indicator_type == 'hash':
        url = f'https://www.virustotal.com/api/v3/files/{indicator}'
        response = requests.get(
            url,
            headers={
                'x-apikey': get_api_key(service='VirusTotal')
            },
            timeout=15
        )
        
        if response.status_code == 404:
            return {
                'hash': indicator,
                'status': 'not_found',
                'message': 'No VirusTotal report exists for this hash.'
            }
        response.raise_for_status()
        

        data = response.json()['data']['attributes']

        stats = data.get('last_analysis_stats', {})
        results = data.get('last_analysis_results', {})

        detections = {}
        for engine, result in results.items():
            if result.get('category') in ('malicious', 'suspicious'):
                detections[engine] = {
                    'category': result.get('category'),
                    'result': result.get('result')
                }

        return {
            'hash': indicator,
            'status': 'found',
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'detection_count': (
                stats.get('malicious', 0) + stats.get('suspicious', 0)
            ),
            'detections': detections,
            'permalink': f'https://www.virustotal.com/gui/file/{indicator}/detection'
        }
    elif indicator_type == 'domain': 
        indicator = indicator.strip().lower().rstrip('.')
        
        response = requests.get(
            f'https://www.virustotal.com/api/v3/domains/{indicator}',
            headers={
                'x-apikey': get_api_key(service='VirusTotal')
            },
            timeout=15
        )
        
        if response.status_code == 404:
            return {
                'domain': indicator,
                'status': 'not_found',
                'message': 'No VirusTotal report exists for this domain.'
            }
        response.raise_for_status()
        
        data = response.json()['data']['attributes']
        stats = data.get('last_analysis_stats', {})
        results = data.get('last_analysis_results', {})
        
        detections = {}
        for engine, result in results.items():
            if result.get('category') in ('malicious', 'suspicious'):
                detections[engine] = {
                    'category': result.get('category'),
                    'result': result.get('result')
                }
        
        return {
            'domain': indicator,
            'status': 'found',
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'detection_count': (
                stats.get('malicious', 0) + stats.get('suspicious', 0)
            ),
            'detections': detections,
            'permalink': f'https://www.virustotal.com/gui/domain/{indicator}'
        }
            
    dump = query(
        url=URL,
        headers=HEADERS,
        parameters=PARAMETERS
    )
    return dump

def query_abuseipdb(indicator: None, indicator_type: str = 'ip') -> str:
    """`query_abuseipdb`: Queries AbuseIPDB for IP information.

    Args:
        indicator (None): The indicator to be queried upon.
        indicator_type (str, optional): The type of indicator. Defaults to 'ip'.

    Raises:
        ValueError: Returns if passed indicator is invalid.

    Returns:
        dict: Dictionary of host information.
        
    Example:
    ```
    aipdb = query_abuseipdb(
        indicator='99.12.13.4'
    )  
    print(aipdb)
    ```
    """
    indicator_type = clean(indicator_type)
    
    BASE_URL = None
    HEADERS = None
    PARAMETERS = None
    
    if indicator_type == 'ip':
        if not is_ip(indicator):
            raise ValueError(f'Indicator({type(indicator)}) `{indicator}` not a valid IPaddress.')
        
        BASE_URL = 'https://api.abuseipdb.com/api/v2/check'
        INDICATOR = indicator
        
        # Can pass many different parameters based on intended usage
        PARAMETERS = {
            'ipAddress': INDICATOR
        }
        HEADERS = {
            'Key': get_api_key(service='AbuseIPDB'),
            'Accept': 'application/json'
        }
        
    dump = query(
        url=BASE_URL,
        headers=HEADERS,
        parameters=PARAMETERS
    )
    return dump

def query_ipinfo(indicator: None, indicator_type: str = 'ip', fields: list = ['ip']) -> dict:
    """`query_ipinfo`: Queries IPInfo for IP information.

    Args:
        indicator (None): The indicator to be queried upon.
        indicator_type (str, optional): The type of indicator. Defaults to 'ip'.
        fields (list, optional): Specify fields rather than 'all' (Detailed in README link for IPInfo docs). Defaults to ['ip'].

    Raises:
        ImportError: Returns if `ipinfo` is not installed.
        ValueError: Returns if passed indicator is invalid.

    Returns:
        dict: Dictionary of host information.
        
    Example:
    ```
    attributes = query_ipinfo(
        indicator='33.31.58.46',
        fields=[
            'ip',
            'as_name'
        ]
    )
    print(attributes)
    ```
    """
    try:
        import ipinfo
    except ImportError:
        print('ERROR:\n- Module `ipinfo` is NOT INSTALLED. Skipping this query...')
        return 'ImportError'
    
    indicator_type = clean(indicator_type)
    
    if indicator_type == 'ip':
        if not is_ip(indicator):
            raise ValueError(f'Indicator({type(indicator)}) `{indicator}` not a valid IPaddress.')
        
        handler = ipinfo.getHandlerLite(
            access_token=get_api_key(service='ipinfo')
        )
        details = handler.getDetails(indicator)
        
        attributes = {}
        for field in fields:
            if hasattr(details, field):
                attributes.update({
                    field: getattr(details, field)
                })
        return attributes
    
def query_shodan(indicator: None, indicator_type: str = 'ip', facets: list = None) -> dict:
    """`query_shodan`: Queries Shodan for host information.

    Args:
        indicator (None): The indicator to query upon.
        indicator_type (str, optional): The type of indicator. Defaults to 'ip'.
        facets (list, optional): README lists potential implementation. Defaults to None.

    Raises:
        ImportError: If `shodan` is not installed.
        ValueError: Returns if passed indicator is invalid.

    Returns:
        dict: A dictionary containing information related to the IP.
        
    Example:
    ```
    host_info = query_shodan(
        indicator='8.8.8.8'
    )
    print(host_info)
    ```
    """
    try:
        import shodan
    except ImportError:
        print('ERROR:\n- Module `shodan` is NOT INSTALLED. Skipping this query...')
        return 'ImportError'
    
    indicator_type = clean(indicator_type)
    
    if indicator_type == 'ip':
        if not is_ip(indicator):
            raise ValueError(f'Indicator({type(indicator)}) `{indicator}` not a valid IPaddress.')
        
        SHODAN_API_KEY = get_api_key(service='shodan')
        api = shodan.Shodan(key=SHODAN_API_KEY)
        host_information = api.host(indicator)
        return host_information
    
if __name__ == '__main__':
    print('query_services.py module loaded')
    
    # TESTING FUNCTIONALITY
    vt = query_virustotal(
        indicator='99.12.13.4'
    )
    print(vt['data'])