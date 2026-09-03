from prismtec.utils.general.helpers import hrx, hr, clean
from prismtec.utils.general.indicators import is_ip
from prismtec.utils.general.path import validate_path, get_current_path

import requests, json

__all__ = [
    s
]

#build_url, get_api_key, query, dump_json

def dump_json(RESPONSE: requests.models.Response) -> str:
    decoded_response = json.loads(RESPONSE.text)
    dump = json.dumps(
        obj=decoded_response,
        sort_keys=True,
        indent=4
    )
    converted_dump = json.loads(dump)
    return converted_dump

def build_url(base_url: str, params: list) -> str:
    temp_url = base_url
    # Remove the final `/` for a directory
    if temp_url[-1] == '/':
        temp_url = temp_url[:-1]
        
    for param in params:
        temp_url += f'/{param}'
    return temp_url

def query(url: str, headers: dict = None,
          parameters: dict = None) -> str:
    RESPONSE = requests.get(
        url=url,
        headers=headers,
        params=parameters
    )
    
    dump = dump_json(RESPONSE=RESPONSE)
    return dump

def get_api_key(service: str) -> str:
    import os
    
    service = clean(service)