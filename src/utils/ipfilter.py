"""Static IP/CIDR allow-list and deny-list support for the edge gateway."""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache


def _networks(value: str):
    networks = []
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return tuple(networks)


@lru_cache(maxsize=1)
def _configured():
    return (
        _networks(os.environ.get("WAF_IP_ALLOWLIST", "")),
        _networks(os.environ.get("WAF_IP_BLOCKLIST", "")),
    )


def ip_decision(client_ip: str) -> str | None:
    """Return 'allowlisted', 'blocklisted' or None for a normal evaluation."""
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return None
    allow, deny = _configured()
    if any(address in net for net in deny):
        return "blocklisted"
    if allow and not any(address in net for net in allow):
        return "not_allowlisted"
    if allow and any(address in net for net in allow):
        return "allowlisted"
    return None
