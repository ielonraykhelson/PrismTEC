from datetime import datetime, timezone

__all__ = [
    'get_timezone_utc'
]

def get_timezone_utc(strformat: str = '%H%M_%d%m%y') -> str:
    current_time = datetime.now(tz=timezone.utc)
    formatted_time = current_time.strftime(strformat)
    return formatted_time
    
if __name__ == '__main__':
    print('generation.py module loaded')