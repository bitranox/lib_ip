# STDLIB
import logging
import socket
from typing import Union

# OWN
import lib_ping
import lib_platform

logger = logging.getLogger()


def get_ip_from_hostname_or_default_gateway_or_localhost(host: Union[str, None] = None) -> Union[str, None]:
    """

    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost(lib_platform.hostname_short)
    >>> assert is_valid_ip_adress(result)
    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost() # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
    >>> assert is_valid_ip_adress(result)
    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost('localhost')
    >>> assert is_valid_ip_adress(result)
    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost('non_exist')  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
    Traceback (most recent call last):
    ...
    ...socket.gaierror: ...
    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost(None)  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
    >>> assert is_valid_ip_adress(result)

    """
    if host is None:
        host_ip = get_ip_default_gateway_or_localhost()
        return host_ip

    host_ip = socket.gethostbyname(host)
    if host.strip().lower() == 'localhost':
        return host_ip
    if ip_is_localhost(host_ip):
        host_ip = get_ip_default_gateway_or_localhost()
    return host_ip


def get_ip_default_gateway_or_localhost() -> Union[str, None]:
    """
    >>> result = get_ip_default_gateway_or_localhost()
    >>> assert is_valid_ip_adress(result)

    """
    host_ip = None
    try:
        host_ip = get_ip_default_gateway()
    except TimeoutError:
        if not host_ip:
            logger.warning('can not get default gateway IP, setting localhost as IP')
            host_ip = socket.gethostbyname('localhost')
    finally:
        return host_ip


def ip_is_localhost(host_ip: str) -> bool:
    """
    >>> ip_is_localhost('127.0.0.1')
    True
    >>> ip_is_localhost('localhost')
    True
    >>> ip_is_localhost('192.168.168.12')
    False
    >>> ip_is_localhost('192.168.168.254')
    False

    """
    host_ip = socket.gethostbyname(host_ip)
    local_host_ip = socket.gethostbyname('localhost')
    if host_ip == local_host_ip or host_ip.startswith('127.'):
        return True
    else:
        return False


def get_ip_default_gateway() -> Union[str, None]:
    """
    >>> result = get_ip_default_gateway()
    >>> assert is_valid_ip_adress(result)

    """
    o_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # noinspection PyBroadException
    try:
        # doesn't even have to be reachable
        o_socket.connect(('1.1.1.1', 1))
        s_ip = str(o_socket.getsockname()[0])  # type: Union[str, None]
    except Exception:
        s_ip = None
    finally:
        o_socket.close()
    return s_ip


def is_internet_connected(ip_adress: str = '1.1.1.1') -> bool:
    """
    >>> is_internet_connected()
    True
    >>> is_internet_connected(ip_adress='www.un-kno-wn.com')
    False

    """
    response = lib_ping.ping(target=ip_adress, times=1)
    return bool(response.reached)


def is_valid_ip_adress(address: str) -> bool:
    """
    check if it is valid IPV4 or IPV6 Adress

    >>> is_valid_ip_adress('1.1.1.1')
    True
    >>> is_valid_ip_adress('::1')
    True
    >>> is_valid_ip_adress('unknown')
    False

    """
    if is_valid_ipv4_address(address) or is_valid_ipv6_address(address):
        return True
    else:
        return False


def is_valid_ipv4_address(address: str) -> bool:
    """
    >>> is_valid_ipv4_address('1.1.1.1')
    True
    >>> is_valid_ipv4_address('1.1.1.')
    False
    >>> is_valid_ipv4_address('unknown')
    False

    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:                      # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:                        # not a valid address
        return False

    return True


def is_valid_ipv6_address(address: str) -> bool:
    """
    >>> is_valid_ipv6_address('::1')
    True
    >>> is_valid_ipv6_address('127.0.0.1')
    False
    >>> is_valid_ipv6_address('unknown')
    False

    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True
