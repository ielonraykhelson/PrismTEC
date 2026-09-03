from prismtec.utils.general.helpers import clean
from prismtec.utils.general.indicators import is_ip
from prismtec.utils.api.calls import build_url, get_api_key, query

def query_virustotal(indicator: None, indicator_type: str='ip') -> str:
    """`query_virustotal`: Queries VirusTotal for IP information.

    Args:
        indicator (None): The indicator to be queried upon.
        indicator_type (str, optional): The type of indicator. Defaults to 'ip'.

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
            'accpet': 'application/json',
            'x-apikey': get_api_key('VirusTotal')
        }
        
    dump = query(
        url=URL,
        headers=HEADERS,
        parameters=PARAMETERS
    )
    return dump