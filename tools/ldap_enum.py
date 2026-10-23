"""
LDAP Enumeration Wrapper
Component: Tool Integration


This is the critical integration seam with Feben's finding_rules.py and
Lidiya's graph.ingest: every entry returned here uses the exact raw LDAP
attribute names (sAMAccountName, distinguishedName, servicePrincipalName,
userAccountControl, objectSid, dNSHostName, operatingSystem, memberOf)
that SecurityRuleEvaluator.evaluate_kerberoastable /
evaluate_asrep_roastable and GraphIngestor.upsert_*_raw already expect -
so their output can be passed straight through with zero translation.

Classified as "Observation" (read-only) in scenarios.md's approval table:
an anonymous or standard-user LDAP bind and search is passive
reconnaissance, not a validation/attack action, so it runs autonomously.
"""

import logging
from typing import List, Optional

from ldap3 import ALL, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException

from tools.models import LDAPEnumerationResult
from tools.scope_guard import OutOfScopeError, assert_in_scope

logger = logging.getLogger("ad_tools.ldap")

DEFAULT_LDAP_PORT = 389
DEFAULT_TIMEOUT_SECONDS = 15

# Attributes pulled per object type - deliberately matches exactly what
# finding_rules.py and graph/ingest.py read, nothing more.
USER_ATTRIBUTES = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "servicePrincipalName",
    "objectSid",
    "objectClass",
    "adminCount",
    "memberOf",
]
GROUP_ATTRIBUTES = ["sAMAccountName", "distinguishedName", "objectSid", "member"]
COMPUTER_ATTRIBUTES = [
    "sAMAccountName",
    "distinguishedName",
    "dNSHostName",
    "operatingSystem",
    "userAccountControl",
    "objectSid",
]


class LDAPEnumerator:
    """
    Usage:
        enumerator = LDAPEnumerator("192.168.56.11")
        enumerator.connect()                                  # anonymous bind
        # or: enumerator.connect(username="user@domain", password="pw")

        users_result = enumerator.enumerate_users()
        for entry in users_result.entries:
            finding = SecurityRuleEvaluator.evaluate_kerberoastable(entry)
            ...
    """

    def __init__(self, target: str, port: int = DEFAULT_LDAP_PORT, use_ssl: bool = False):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self._conn: Optional[Connection] = None
        self._base_dn: Optional[str] = None
        self._resolved_ip: Optional[str] = None

    def connect(self, username: Optional[str] = None, password: Optional[str] = None) -> bool:
        """
        Binds to the target LDAP server. Anonymous bind if no credentials
        given. Returns True on success, False on failure (check
        self.last_error for details rather than raising, so callers can
        record a clean "collection failed" result instead of crashing).
        """
        self.last_error: Optional[str] = None
        try:
            self._resolved_ip = assert_in_scope(self.target)
        except OutOfScopeError as exc:
            self.last_error = str(exc)
            logger.error("Scope check failed for LDAP connect: %s", exc)
            return False

        try:
            server = Server(self._resolved_ip, port=self.port, use_ssl=self.use_ssl, get_info=ALL)
            if username and password:
                self._conn = Connection(
                    server, user=username, password=password,
                    auto_bind=True, receive_timeout=DEFAULT_TIMEOUT_SECONDS,
                )
            else:
                self._conn = Connection(
                    server, auto_bind=True, receive_timeout=DEFAULT_TIMEOUT_SECONDS,
                )
            self._base_dn = self._discover_base_dn(server)
            logger.info(
                "LDAP bind to %s succeeded (base DN: %s, anonymous=%s)",
                self._resolved_ip, self._base_dn, not bool(username),
            )
            return True
        except LDAPException as exc:
            self.last_error = str(exc)
            logger.error("LDAP bind to %s failed: %s", self._resolved_ip, exc)
            self._conn = None
            return False

    @staticmethod
    def _discover_base_dn(server: Server) -> Optional[str]:
        try:
            naming_contexts = server.info.naming_contexts if server.info else None
            if naming_contexts:
                # Prefer the context that looks like a domain DN over config/schema contexts.
                for ctx in naming_contexts:
                    if ctx.upper().startswith("DC="):
                        return ctx
                return naming_contexts[0]
        except Exception:  # noqa: BLE001 - base DN discovery is best-effort
            pass
        return None

    def disconnect(self) -> None:
        if self._conn is not None:
            self._conn.unbind()
            self._conn = None

    def _search(self, filter_str: str, attributes: List[str]) -> LDAPEnumerationResult:
        command = f"ldapsearch -x -H ldap://{self.target}:{self.port} -b '{self._base_dn}' '{filter_str}'"

        if self._conn is None:
            return LDAPEnumerationResult(
                tool_name="ldap3",
                command=command,
                output="",
                status="error",
                error=self.last_error or "Not connected - call connect() first",
                base_dn=self._base_dn,
            )

        if not self._base_dn:
            return LDAPEnumerationResult(
                tool_name="ldap3",
                command=command,
                output="",
                status="error",
                error="No base DN discovered; cannot scope the search",
                base_dn=None,
            )

        try:
            self._conn.search(
                search_base=self._base_dn,
                search_filter=filter_str,
                search_scope=SUBTREE,
                attributes=attributes,
            )
        except LDAPException as exc:
            logger.error("LDAP search failed (%s): %s", filter_str, exc)
            return LDAPEnumerationResult(
                tool_name="ldap3",
                command=command,
                output="",
                status="error",
                error=str(exc),
                base_dn=self._base_dn,
            )

        entries = []
        for entry in self._conn.entries:
            raw: dict = {}
            for attr in attributes:
                if attr not in entry.entry_attributes:
                    continue
                value = entry[attr].value
                raw[attr] = value
            raw["distinguishedName"] = entry.entry_dn
            entries.append(raw)

        return LDAPEnumerationResult(
            tool_name="ldap3",
            command=command,
            output=f"{len(entries)} entries returned for filter {filter_str}",
            status="success",
            base_dn=self._base_dn,
            entries=entries,
            entry_count=len(entries),
        )

    def enumerate_users(self) -> LDAPEnumerationResult:
        """
        Returns User objects (excludes computer accounts). Each entry has
        the exact keys SecurityRuleEvaluator.evaluate_kerberoastable() and
        evaluate_asrep_roastable() read directly.
        """
        return self._search(
            "(&(objectClass=user)(objectCategory=person))", USER_ATTRIBUTES
        )

    def enumerate_groups(self) -> LDAPEnumerationResult:
        return self._search("(objectClass=group)", GROUP_ATTRIBUTES)

    def enumerate_computers(self) -> LDAPEnumerationResult:
        return self._search("(objectClass=computer)", COMPUTER_ATTRIBUTES)

    def enumerate_kerberoastable_candidates(self) -> LDAPEnumerationResult:
        """
        Narrower, more efficient search for the Kerberoasting passive
        indicator from scenarios.md: accounts with a non-empty SPN, user
        objects only (computer accounts excluded via !objectClass=computer).
        """
        return self._search(
            "(&(servicePrincipalName=*)(!(objectClass=computer)))", USER_ATTRIBUTES
        )

    def enumerate_asrep_candidates(self) -> LDAPEnumerationResult:
        """
        Narrower search for the AS-REP Roasting passive indicator:
        DONT_REQ_PREAUTH bit (0x400000 = 4194304) set via the LDAP_MATCHING
        rule OID for bitwise AND, as specified in scenarios.md.
        """
        return self._search(
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)", USER_ATTRIBUTES
        )

    def __enter__(self) -> "LDAPEnumerator":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
