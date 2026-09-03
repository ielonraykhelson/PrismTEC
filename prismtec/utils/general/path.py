from prismtec.utils.general.helpers import clean

__all__ = [
    'validate_path',
    'get_current_path'
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
    import os
    return os.getcwd()