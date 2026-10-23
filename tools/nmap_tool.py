import ipaddress
import subprocess

from agent.models import CapabilityTier, ToolResult
from tools.base import SecurityTool


class NmapTool(SecurityTool):
    name = "network_discovery"
    tier = CapabilityTier.READ_ONLY
    risk_description = "Passive port discovery across standard Active Directory infrastructure ports."

    # Authorized subnet boundary (GOAD-Light default host-only network)
    AUTHORIZED_SCOPE = ipaddress.ip_network("192.168.56.0/24")

    # Standard Active Directory ports: Kerberos, RPC, LDAP, SMB, Global Catalog
    AD_PORTS = "88,135,389,445,3268,3269"

    def _is_in_scope(self, target: str) -> bool:
        try:
            return ipaddress.ip_address(target) in self.AUTHORIZED_SCOPE
        except ValueError:
            return False

    def run(self, target: str, **kwargs) -> ToolResult:
        if not self._is_in_scope(target):
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output=f"Target {target} is outside the authorized lab scope ({self.AUTHORIZED_SCOPE}).",
            )

        command = [
            "nmap",
            "-sT",              # TCP connect scan (doesn't require root privileges)
            "-Pn",              # Treat host as online (bypasses Windows ICMP echo drops)
            "-p", self.AD_PORTS,
            "--open",           # Only report open ports
            target,
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Detect cases where Nmap ran with exit code 0 but reported host down
            if "0 hosts up" in result.stdout:
                return ToolResult(
                    tool=self.name,
                    target=target,
                    status="failed",
                    output=f"Host {target} is unreachable. Verify that the lab VM is booted and networking is active.",
                )

            if result.returncode == 0:
                return ToolResult(
                    tool=self.name,
                    target=target,
                    status="success",
                    output=result.stdout,
                )

            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output=result.stderr or "Nmap scan failed.",
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.name,
                target=target,
                status="timeout",
                output="Nmap scan exceeded the 60-second timeout.",
            )

        except FileNotFoundError:
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output="Nmap is not installed or is not available in PATH.",
            )