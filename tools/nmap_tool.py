import subprocess

from agent.models import ToolResult
from tools.base import SecurityTool


class NmapTool(SecurityTool):
    name = "nmap"

    def run(self, target: str) -> ToolResult:
        command = [
            "nmap",
            "-sV",
            target,
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120,
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
                output=result.stderr,
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.name,
                target=target,
                status="timeout",
                output="Nmap scan exceeded the 120-second timeout.",
            )

        except FileNotFoundError:
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output="Nmap is not installed or is not available in PATH.",
            )
