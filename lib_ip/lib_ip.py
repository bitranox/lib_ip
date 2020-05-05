# STDLIB
import logging
import socket
from typing import Union

# OWN
import lib_ping         # type: ignore
import lib_platform     # type: ignore

logger = logging.getLogger()


def get_ip_from_hostname_or_default_gateway_or_localhost(host: Union[str, None] = None) -> Union[str, None]:
    """
    >>> import unittest
    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost(lib_platform.hostname_short)
    >>> assert is_valid_ip_adress(result)
    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost() # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
    >>> assert is_valid_ip_adress(result)
    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost('localhost')
    >>> assert is_valid_ip_adress(result)
    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost('127.0.0.1')
    >>> assert is_valid_ip_adress(result)
    >>> unittest.TestCase().assertRaises(ConnectionError, get_ip_from_hostname_or_default_gateway_or_localhost, 'non_exist')
    >>> result = get_ip_from_hostname_or_default_gateway_or_localhost(None)  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
    >>> assert is_valid_ip_adress(result)
    """
    if host is None:
        host_ip = get_host_ip_or_localhost()
        return host_ip

    try:
        host_ip = socket.gethostbyname(host)
    # under pypy _socket.gaierror, anywhere else socket.gaierror if IP can not be resolved
    except Exception:
        raise ConnectionError('can not resolve Hostname "{host}"'.format(host=host))

    if host.strip().lower() == 'localhost':
        return host_ip
    if ip_is_localhost(host_ip):
        host_ip = get_host_ip_or_localhost()
    return host_ip


def get_host_ip_or_localhost() -> Union[str, None]:
    """
    >>> result = get_host_ip_or_localhost()
    >>> assert is_valid_ip_adress(result)

    """
    host_ip = get_host_ip()

    if not host_ip:                                                                     # pragma: no cover
        logger.warning('can not get default gateway IP, setting localhost as IP')       # pragma: no cover
        host_ip = socket.gethostbyname('localhost')                                     # pragma: no cover
    return host_ip


def ip_is_localhost(host_ip: str) -> bool:
    """
    >>> ip_is_localhost('127.0.0.1')
    True
    >>> ip_is_localhost('localhost')
    True
    >>> ip_is_localhost('192.168.168.17')
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


def get_host_ip() -> Union[str, None]:
    """
    >>> result = get_host_ip()
    >>> assert is_valid_ip_adress(result)

    """
    o_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # noinspection PyBroadException
    try:
        # doesn't even have to be reachable
        o_socket.connect(('1.1.1.1', 1))
        s_ip = str(o_socket.getsockname()[0])  # type: Union[str, None]
    except Exception:           # pragma: no cover
        s_ip = None             # pragma: no cover
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
    except AttributeError:                      # pragma: no cover      # no inet_pton here, sorry
        try:                                    # pragma: no cover
            socket.inet_aton(address)           # pragma: no cover
        except socket.error:                    # pragma: no cover
            return False                        # pragma: no cover
        return address.count('.') == 3          # pragma: no cover
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


def nslookup(hostname: str) -> str:
    """
    >>> import unittest
    >>> assert nslookup('www.rotek.at') is not None
    >>> unittest.TestCase().assertRaises(ConnectionError, nslookup, 'unknown.host.com')

    """
    try:
        host_ip = socket.gethostbyname(hostname)
        return host_ip
    # under pypy _socket.gaierror, anywhere else socket.gaierror if IP can not be resolved
    except Exception:
        raise ConnectionError('can not resolve Hostname "{hostname}"'.format(hostname=hostname))
