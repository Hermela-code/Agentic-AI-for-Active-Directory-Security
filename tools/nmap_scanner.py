"""
Nmap Wrapper
Component: Tool Integration


Read-only port/service discovery - classified as "Observation" level in
scenarios.md's approval table, so this runs autonomously with no HITL gate.
Shells out to the real `nmap` binary and parses its XML output (-oX -),
which is far more reliable to parse than human-readable stdout.
"""

import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Optional

from tools.models import NmapScanResult, OpenPort, ToolExecutionResult
from tools.scope_guard import OutOfScopeError, assert_in_scope

logger = logging.getLogger("ad_tools.nmap")

# Ports relevant to Active Directory discovery - matches the set used in
# the Backend API integration note's example command.
AD_RELEVANT_PORTS = "53,88,135,139,389,443,445,464,593,636,3268,3269,3389,5985,9389"

DEFAULT_TIMEOUT_SECONDS = 120


def _nmap_binary_available() -> bool:
    return shutil.which("nmap") is not None


def run_port_scan(
    target: str,
    ports: str = AD_RELEVANT_PORTS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> NmapScanResult:
    """
    Runs `nmap -sT -Pn -p <ports> -sV <target>` and returns a structured
    result. `-sT` (TCP connect scan) avoids requiring raw-socket privileges;
    `-Pn` skips host-up ping checks, which GOAD-Light VMs often block;
    `-sV` grabs service/version banners, useful for telling a real DC apart
    from a decoy.
    """
    try:
        resolved_ip = assert_in_scope(target)
    except OutOfScopeError as exc:
        logger.error("Scope check failed for nmap scan: %s", exc)
        return NmapScanResult(
            tool_name="nmap",
            command=f"nmap -sT -Pn -sV -p {ports} {target}",
            output="",
            status="error",
            error=str(exc),
            host=target,
        )

    if not _nmap_binary_available():
        return NmapScanResult(
            tool_name="nmap",
            command=f"nmap -sT -Pn -sV -p {ports} {target}",
            output="",
            status="error",
            error="nmap binary not found on PATH. Install with: sudo apt install nmap",
            host=target,
        )

    command = ["nmap", "-sT", "-Pn", "-sV", "-p", ports, "-oX", "-", resolved_ip]
    command_str = " ".join(command[:-2] + [resolved_ip])  # pretty command for logging, without -oX -

    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout_seconds, check=False
        )
    except subprocess.TimeoutExpired:
        logger.warning("nmap scan of %s timed out after %ds", resolved_ip, timeout_seconds)
        return NmapScanResult(
            tool_name="nmap",
            command=command_str,
            output="",
            status="timeout",
            error=f"Scan exceeded {timeout_seconds}s timeout",
            host=target,
        )
    except OSError as exc:
        return NmapScanResult(
            tool_name="nmap",
            command=command_str,
            output="",
            status="error",
            error=str(exc),
            host=target,
        )

    if proc.returncode != 0:
        return NmapScanResult(
            tool_name="nmap",
            command=command_str,
            output=proc.stdout,
            status="error",
            error=proc.stderr.strip() or f"nmap exited with code {proc.returncode}",
            host=target,
        )

    open_ports = _parse_nmap_xml(proc.stdout)
    port_numbers = {p.port for p in open_ports}

    has_kerberos = 88 in port_numbers
    has_ldap = 389 in port_numbers or 3268 in port_numbers
    has_smb = 445 in port_numbers

    return NmapScanResult(
        tool_name="nmap",
        command=command_str,
        output=_human_readable_summary(resolved_ip, open_ports),
        status="success",
        host=target,
        open_ports=open_ports,
        has_kerberos=has_kerberos,
        has_ldap=has_ldap,
        has_smb=has_smb,
        likely_domain_controller=has_kerberos and has_ldap and has_smb,
    )


def _parse_nmap_xml(xml_output: str) -> List[OpenPort]:
    ports: List[OpenPort] = []
    if not xml_output.strip():
        return ports

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        logger.warning("Failed to parse nmap XML output; returning no ports")
        return ports

    for port_el in root.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        service_el = port_el.find("service")
        ports.append(
            OpenPort(
                port=int(port_el.get("portid")),
                protocol=port_el.get("protocol", "tcp"),
                service=service_el.get("name") if service_el is not None else None,
                product=service_el.get("product") if service_el is not None else None,
                version=service_el.get("version") if service_el is not None else None,
            )
        )
    return ports


def _human_readable_summary(host: str, ports: List[OpenPort]) -> str:
    if not ports:
        return f"No open ports found on {host} within the scanned range."
    lines = [f"PORT      STATE   SERVICE"]
    for p in sorted(ports, key=lambda x: x.port):
        svc = p.service or "unknown"
        extra = f" {p.product} {p.version}".rstrip() if p.product else ""
        lines.append(f"{p.port}/{p.protocol:<5} open    {svc}{extra}")
    return "\n".join(lines)
