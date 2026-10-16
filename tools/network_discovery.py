import shutil
import subprocess

from agent.models import CapabilityTier, ToolResult
from tools.base import SecurityTool
from tools.safety import UnauthorizedTargetError, enforce_scope


class NetworkDiscoveryTool(SecurityTool):
    """
    Wraps Nmap service/version detection. Read-only reconnaissance —
    no exploitation, no credential use, safe to run without approval.

    analyzer.py's _analyze_network_discovery() expects `output` to be
    the raw nmap text (it string-matches on things like "88/tcp" and
    "kerberos"), so this wrapper intentionally returns nmap's stdout
    as-is rather than parsing it into JSON.
    """

    name = "network_discovery"
    tier = CapabilityTier.READ_ONLY
    risk_description = (
        "Passive/semi-active port and service-version scan. No credentials "
        "used, no exploitation performed."
    )

    def __init__(self, timeout_seconds: int = 120):
        self.timeout_seconds = timeout_seconds

    def run(self, target: str, **kwargs) -> ToolResult:
        try:
            enforce_scope(target)
        except UnauthorizedTargetError as e:
            return ToolResult(
                tool=self.name, target=target, status="failed", output=str(e)
            )

        if shutil.which("nmap") is None:
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output="nmap is not installed or not on PATH.",
            )

        cmd = ["nmap", "-sV", "-Pn", target]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output=f"nmap scan timed out after {self.timeout_seconds}s.",
            )
        except Exception as e:
            return ToolResult(
                tool=self.name, target=target, status="failed", output=str(e)
            )

        if proc.returncode != 0:
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output=proc.stderr or proc.stdout or "nmap exited with a non-zero status.",
            )

        return ToolResult(
            tool=self.name,
            target=target,
            status="success",
            output=proc.stdout,
        )
