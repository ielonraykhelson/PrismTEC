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