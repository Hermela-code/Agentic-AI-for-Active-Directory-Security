import os

# Per the project's Security Rules (section 17 of the project doc):
# "Stay within the defined authorized scope" / "Never attack arbitrary
# external systems". This is a simple allowlist check every tool wrapper
# must call before executing anything against a target.
#
# Override via env var for different lab setups, e.g.:
#   export AUTHORIZED_TARGETS="192.168.56.10,192.168.56.11,192.168.56.0/24"
_DEFAULT_AUTHORIZED_TARGETS = ["192.168.56.11"]  # matches agent.py's __main__ example


def get_authorized_targets() -> list[str]:
    raw = os.getenv("AUTHORIZED_TARGETS")
    if raw:
        return [t.strip() for t in raw.split(",") if t.strip()]
    return _DEFAULT_AUTHORIZED_TARGETS


class UnauthorizedTargetError(Exception):
    pass


def enforce_scope(target: str) -> None:
    """
    Raises UnauthorizedTargetError if target is not in the authorized list.
    NOTE: exact-match / simple CIDR string check only — intentionally
    conservative. Extend with real CIDR parsing (ipaddress module) if the
    team needs subnet-wide authorization for GOAD-Light.
    """
    authorized = get_authorized_targets()
    if target in authorized:
        return

    import ipaddress

    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        raise UnauthorizedTargetError(
            f"Target '{target}' is not a valid IP and not in the authorized allowlist."
        )

    for entry in authorized:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if target_ip in network:
                return
        except ValueError:
            continue

    raise UnauthorizedTargetError(
        f"Target '{target}' is not in the authorized scope: {authorized}"
    )
