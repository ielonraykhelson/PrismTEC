from prismtec.utils.general.helpers import clean
from prismtec.utils.general.path import get_current_path, get_assets_path, validate_path

import requests, json

__all__ = [
    'dump_json',
    'get_api_key',
    'build_url',
    'query'
]

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

def get_api_key(service: str = None) -> str:
    import os
    
    #debug
    if service is None:
        target_path = f'{get_assets_path()}\\CONFIG.json'
        return f'{validate_path(path=target_path)} : `{target_path}`'
    
    service = clean(service)
    try:
        file_path = f'{get_assets_path()}\\CONFIG.json'
        with open(file_path, 'r') as file:
            data = json.load(file)
            api_key = data['API-keys'][service]
    except FileNotFoundError:
        raise FileNotFoundError(f'{file_path} NOT FOUND AT {get_current_path()}')
    
    return api_key

if __name__ == '__main__':
    print('calls.py module loaded')
    print(get_api_key())