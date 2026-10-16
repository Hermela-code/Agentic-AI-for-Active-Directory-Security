import shutil
import subprocess

from agent.models import CapabilityTier, ToolResult
from tools.base import SecurityTool
from tools.safety import UnauthorizedTargetError, enforce_scope


class DomainEnumerationTool(SecurityTool):
    """
    Wraps NetExec's LDAP module for anonymous-bind domain/DC banner
    grabbing. Read-only — no credentials supplied, just an unauthenticated
    LDAP connection attempt.

    analyzer.py's _analyze_domain_enum() expects the raw NetExec banner
    text, which looks like:
        LDAP   10.0.0.10   389   DC01   [*] Windows Server 2019 ...
            (name:DC01) (domain:sevenkingdoms.local) (signing:None) ...
    and regex-extracts (name:...) and (domain:...) directly from it.

    If the DC rejects anonymous LDAP (common hardening), NetExec's error
    text includes the well-known AD error substring "successful bind
    must be completed" — we detect that and set status="auth_required"
    so the agent knows directory queries need credentials.
    """

    name = "domain_enumeration"
    tier = CapabilityTier.READ_ONLY
    risk_description = (
        "Unauthenticated (anonymous bind) LDAP query for domain/DC banner "
        "information. No credentials used, no directory objects modified."
    )

    def __init__(self, timeout_seconds: int = 60):
        self.timeout_seconds = timeout_seconds

    def run(self, target: str, **kwargs) -> ToolResult:
        try:
            enforce_scope(target)
        except UnauthorizedTargetError as e:
            return ToolResult(
                tool=self.name, target=target, status="failed", output=str(e)
            )

        binary = shutil.which("nxc") or shutil.which("netexec")
        if binary is None:
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output="netexec/nxc is not installed or not on PATH.",
            )

        cmd = [binary, "ldap", target]

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
                output=f"netexec ldap timed out after {self.timeout_seconds}s.",
            )
        except Exception as e:
            return ToolResult(
                tool=self.name, target=target, status="failed", output=str(e)
            )

        combined_output = (proc.stdout or "") + (proc.stderr or "")

        if "successful bind must be completed" in combined_output.lower():
            return ToolResult(
                tool=self.name,
                target=target,
                status="auth_required",
                output=combined_output,
            )

        if proc.returncode != 0 and "(domain:" not in combined_output:
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output=combined_output or "netexec exited with a non-zero status.",
            )

        if not combined_output.strip():
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output="netexec ran but produced no output — target may not be running LDAP/AD.",
            )

        return ToolResult(
            tool=self.name,
            target=target,
            status="success",
            output=combined_output,
        )
