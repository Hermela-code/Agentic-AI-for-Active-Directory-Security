"""
Authorized Scope Enforcement
Component: Tool Integration
Author: Meseret Telke

SETUP.md rule #8: "Work only against the authorized GOAD-Light environment."
The Backend API note confirms the authorized scope is 192.168.56.0/24.

Every tool wrapper in this package calls assert_in_scope() before touching
the network. This is defense in depth: even if the agent or backend never
calls it, the tool layer itself refuses to run against anything outside
the authorized range.
"""

import ipaddress
import os
import socket
from typing import Optional

DEFAULT_AUTHORIZED_SCOPE = "192.168.56.0/24"


class OutOfScopeError(Exception):
    """Raised when a target falls outside the authorized testing range."""


def _get_authorized_network() -> ipaddress.IPv4Network:
    scope = os.environ.get("AUTHORIZED_SCOPE", DEFAULT_AUTHORIZED_SCOPE)
    return ipaddress.ip_network(scope, strict=False)


def resolve_target(target: str) -> str:
    """
    Resolves a hostname to an IP for scope checking. If `target` is already
    an IP literal, returns it unchanged. Raises OutOfScopeError (not a
    generic resolution error) if resolution fails, since an unresolvable
    target can't be verified as in-scope and must not be assumed safe.
    """
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise OutOfScopeError(
            f"Could not resolve '{target}' to verify it is within the authorized scope. "
            "Refusing to proceed without scope confirmation."
        ) from exc


def assert_in_scope(target: str, authorized_scope: Optional[str] = None) -> str:
    """
    Verifies `target` (IP or hostname) falls within the authorized scope.
    Returns the resolved IP on success. Raises OutOfScopeError on failure.

    Call this as the first line of every tool wrapper's entry point.
    """
    network = (
        ipaddress.ip_network(authorized_scope, strict=False)
        if authorized_scope
        else _get_authorized_network()
    )
    resolved_ip = resolve_target(target)

    if ipaddress.ip_address(resolved_ip) not in network:
        raise OutOfScopeError(
            f"Target '{target}' (resolved: {resolved_ip}) is outside the authorized "
            f"scope ({network}). Refusing to execute."
        )
    return resolved_ip
