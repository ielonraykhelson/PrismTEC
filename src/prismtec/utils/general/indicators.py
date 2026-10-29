from prismtec.utils.general.helpers import hr, hrx
import ipaddress

__all__ = [
    'is_ip'
]

def is_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
if __name__ == '__main__':
    print('indicators.py module loaded')