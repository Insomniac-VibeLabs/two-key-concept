"""Where an endpoint really is, from its URL host. Never from a declared flag.

``host_is_loopback`` accepts ``localhost`` and loopback IP literals.
``host_is_local`` also accepts private-range IP literals (RFC 1918, IPv6
unique-local). A DNS name other than ``localhost`` is not local, even if it
resolves to a private address today: names can be repointed. Link-local
addresses (for example 169.254.169.254, a cloud metadata service) are not local.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

LOOPBACK_NAMES = {"localhost"}


def url_host(url: str | None) -> str:
    try:
        return (urlparse(url or "").hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return None


def host_is_loopback(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if host in LOOPBACK_NAMES:
        return True
    ip = _ip(host)
    return ip is not None and ip.is_loopback


def host_is_local(host: str) -> bool:
    if host_is_loopback(host):
        return True
    ip = _ip((host or "").lower())
    if ip is None or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return host_is_local(str(ip.ipv4_mapped))
    return ip.is_private
