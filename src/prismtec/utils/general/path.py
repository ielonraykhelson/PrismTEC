from pathlib import Path

from prismtec.utils.general.helpers import clean

__all__ = [
    'validate_path',
    'get_current_path',
    'get_assets_path',
    'get_reports_path',
    'append_to_assets_path',
    'append_to_reports_path'
]

def validate_path(path: str, path_type: str='both') -> bool:
    import os
    
    dir_aliases = ['dir', 'directory', 'd']
    file_aliases = ['file','f']
    
    path_type = clean(path_type)
    
    EXISTS = False
    if path_type in file_aliases:
        EXISTS = os.path.isfile(path)
    elif path_type in dir_aliases:
        EXISTS = os.path.isdir(path)
    else:
        EXISTS = os.path.exists(path)
    return EXISTS

def get_current_path():
    return str(Path(__file__).resolve().parents[4])

def get_assets_path():
    return str(Path(get_current_path()) / 'src' / 'prismtec' / 'assets')

def append_to_assets_path(path: str) -> str:
    path = Path(path)
    if path.is_absolute():
        return str(path)
    if path.parts[:2] == ('src', 'prismtec'):
        return str(Path(get_current_path()) / path)
    return str(Path(get_assets_path()) / path)

def get_reports_path():
    return str(Path(get_current_path()) / 'src' / 'prismtec' / 'reports')

def append_to_reports_path(path: str) -> str:
    path = Path(path)
    if path.is_absolute():
        return str(path)
    if path.parts[:2] == ('src', 'prismtec'):
        return str(Path(get_current_path()) / path)
    return str(Path(get_reports_path()) / path)

if __name__ == '__main__':
    print('path.py module loaded')
    print(append_to_assets_path(path='TARGET.json'))
    
    # Testing functionality
    # ROOT_PATH = get_current_path()
    # path = get_current_path()
    # print(f'Path: `{path}`\n- {validate_path(path)}')
    # path_a = path + '\\src\\prismtec\\enrichment\\'
    # print(f'Path: `{path_a}`\n- {validate_path(path_a)}')