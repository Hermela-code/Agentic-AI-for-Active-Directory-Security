"""
tools/capabilities.py
Component: Tool Integration — adapter layer

agent.py calls:
    tool = self.tools.get_tool(capability)
    tool.tier, tool.risk_description
    tool.run(target, **kwargs) -> agent.models.ToolResult

The new tool implementations (nmap_scanner.py, netexec_wrapper.py,
ldap_enum.py) are plain functions returning their own Pydantic models
(NmapScanResult, ToolExecutionResult, LDAPEnumerationResult,
AdminCheckResult) — a different, newer, and better-designed contract, but
not the one agent.py expects.

These adapter classes bridge the two WITHOUT changing agent.py at all:
each wraps one function, converts its result into agent.models.ToolResult,
and exposes the .tier / .risk_description / .run() shape agent.py needs.
"""

import json
import os

from agent.models import CapabilityTier, ToolResult
from tools.base import SecurityTool

from tools import nmap_scanner
from tools import netexec_wrapper
from tools import ldap_enum


class NetworkDiscoveryCapability(SecurityTool):
    """Adapts tools.nmap_scanner.run_port_scan() — Observation level."""

    name = "network_discovery"
    tier = CapabilityTier.READ_ONLY
    risk_description = (
        "TCP connect scan + service/version detection against AD-relevant "
        "ports. No credentials used, no exploitation performed."
    )

    def run(self, target: str, **kwargs) -> ToolResult:
        result = nmap_scanner.run_port_scan(target)
        return ToolResult(
            tool=self.name,
            target=target,
            status=result.status,
            output=result.output or (result.error or ""),
        )


class DomainEnumerationCapability(SecurityTool):
    """Adapts tools.netexec_wrapper.smb_enum() — Observation level."""

    name = "domain_enumeration"
    tier = CapabilityTier.READ_ONLY
    risk_description = (
        "Unauthenticated SMB banner grab (nxc smb) for OS/hostname/domain "
        "name and signing status. No credentials used."
    )

    def run(self, target: str, **kwargs) -> ToolResult:
        result = netexec_wrapper.smb_enum(target)
        return ToolResult(
            tool=self.name,
            target=target,
            status=result.status,
            output=result.output or (result.error or ""),
        )


class ADUserEnumerationCapability(SecurityTool):
    """
    Adapts tools.ldap_enum.LDAPEnumerator — runs BOTH the Kerberoasting
    and AS-REP candidate searches and merges entries by sAMAccountName,
    returning a JSON-encoded list in ToolResult.output so analyzer.py can
    json.loads() it and run each entry through Feben's
    backend.security.finding_rules.SecurityRuleEvaluator.

    Observation level per scenarios.md — a standard LDAP search, no
    credential validation or ticket requests.
    """

    name = "ad_user_enumeration"
    tier = CapabilityTier.READ_ONLY
    risk_description = (
        "Read-only LDAP queries for Kerberoastable (SPN) and AS-REP-"
        "roastable (DONT_REQ_PREAUTH) account indicators. No tickets "
        "requested, no credentials validated."
    )

    def run(self, target: str, **kwargs) -> ToolResult:
        enumerator = ldap_enum.LDAPEnumerator(target)
        connected = enumerator.connect()
        if not connected:
            return ToolResult(
                tool=self.name, target=target, status="failed",
                output=json.dumps({"status": "error", "error": enumerator.last_error}),
            )

        try:
            kerb_result = enumerator.enumerate_kerberoastable_candidates()
            asrep_result = enumerator.enumerate_asrep_candidates()
        finally:
            enumerator.disconnect()

        if kerb_result.status != "success" and asrep_result.status != "success":
            return ToolResult(
                tool=self.name, target=target, status="failed",
                output=json.dumps({
                    "status": "error",
                    "error": kerb_result.error or asrep_result.error or "LDAP search failed",
                }),
            )

        merged: dict = {}
        for entry in (kerb_result.entries or []) + (asrep_result.entries or []):
            sam = entry.get("sAMAccountName")
            if sam:
                merged.setdefault(sam, {}).update(entry)

        return ToolResult(
            tool=self.name,
            target=target,
            status="success",
            output=json.dumps(list(merged.values())),
        )


class CheckAdminAccessCapability(SecurityTool):
    """
    Adapts tools.netexec_wrapper.check_admin_access() — THE
    REQUIRES_APPROVAL capability. Credentials come from environment
    variables, never from LLM-generated params, so the model can request
    this action but can never supply or invent the credentials itself:
        AD_TEST_USERNAME, AD_TEST_PASSWORD, AD_TEST_DOMAIN (optional)

    This is a Controlled Validation action per scenarios.md — must only
    run after human approval, which agent.py's existing
    request_human_approval() gate already enforces based on .tier below.
    """

    name = "check_admin_access"
    tier = CapabilityTier.REQUIRES_APPROVAL
    risk_description = (
        "Validates supplied lab credentials against the target via SMB "
        "(nxc smb --shares) and reports local admin status. Generates "
        "authentication attempts and Windows Security event log entries "
        "on the target."
    )

    def run(self, target: str, **kwargs) -> ToolResult:
        username = os.getenv("AD_TEST_USERNAME")
        password = os.getenv("AD_TEST_PASSWORD")
        domain = os.getenv("AD_TEST_DOMAIN")

        if not username or not password:
            return ToolResult(
                tool=self.name, target=target, status="failed",
                output="AD_TEST_USERNAME / AD_TEST_PASSWORD not set — cannot run a "
                       "credentialed check. Set these env vars with authorized lab credentials.",
            )

        result = netexec_wrapper.check_admin_access(target, username, password, domain=domain)
        return ToolResult(
            tool=self.name,
            target=target,
            status=result.status,
            output=json.dumps({
                "output": result.output,
                "is_admin": result.is_admin,
                "shares": result.shares,
            }),
        )
