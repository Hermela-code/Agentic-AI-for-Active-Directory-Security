import ipaddress
import subprocess
from typing import Dict, List, Optional
from agent.models import ToolResult
from tools.base import SecurityTool


class DomainEnumerationTool(SecurityTool):
    name = "domain_enumeration"

    # Authorized subnet boundaries (GOAD-Light default host-only network)
    AUTHORIZED_SCOPE = ipaddress.ip_network("192.168.56.0/24")

    # Safe enumeration flags
    ALLOWED_OPERATIONS: Dict[str, List[str]] = {
        "dc-list": ["--dc-list"],
        "users": ["--users"],
        "pass-pol": ["--pass-pol"],
    }

    def _is_in_scope(self, target: str) -> bool:
        """Ensures the target IP falls strictly within authorized lab subnets."""
        try:
            ip = ipaddress.ip_address(target)
            return ip in self.AUTHORIZED_SCOPE
        except ValueError:
            # Reject raw hostnames that cannot be verified against the IP CIDR
            return False

    def run(self, target: str, operation: str = "dc-list", **kwargs) -> ToolResult:
        """
        Executes non-destructive directory enumeration against an in-scope AD target.
        """
        if not self._is_in_scope(target):
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output=f"Target {target} is outside the authorized lab scope (192.168.56.0/24).",
            )

        if operation not in self.ALLOWED_OPERATIONS:
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output=(
                    f"Unsupported operation '{operation}'. "
                    f"Allowed operations: {list(self.ALLOWED_OPERATIONS.keys())}"
                ),
            )

        command = ["nxc", "ldap", target] + self.ALLOWED_OPERATIONS[operation]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120,
            )

            combined_output = (result.stdout or "") + (result.stderr or "")

            # Check if directory access was denied due to lack of credentials
            if "successful bind must be completed" in combined_output:
                return ToolResult(
                    tool=self.name,
                    target=target,
                    status="auth_required",
                    output=combined_output.strip(),
                )

            status = "success" if result.returncode == 0 else "failed"

            return ToolResult(
                tool=self.name,
                target=target,
                status=status,
                output=combined_output.strip(),
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.name,
                target=target,
                status="timeout",
                output="LDAP query timed out after 120 seconds.",
            )

        except FileNotFoundError:
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output="NetExec (nxc) binary not found on system PATH.",
            )