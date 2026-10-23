"""
Tool Output Models
Component: Tool Integration


ToolExecutionResult mirrors the shape Wintana's backend already expects
for GET /investigations/{id}/executions (see Backend_API_Integration_Note):

    {
      "tool_name": "nmap",
      "command": "nmap -sT -Pn -p 88,135,389,445,3268,3269 192.168.56.11",
      "output": "...",
      "status": "success",
      "executed_at": "..."
    }

Every wrapper in this package returns one of these (or a subclass) so the
agent/backend can log it directly without reshaping anything. `status` is
also exactly what Feben's finding_rules.SecurityRuleEvaluator.
validate_telemetry_payload() checks for ("error" | "failed" | "timeout"
mean "skip cleanly, don't invent a finding").
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ToolExecutionResult(BaseModel):
    tool_name: str
    command: str
    output: str
    status: str                             # "success" | "error" | "failed" | "timeout"
    error: Optional[str] = None
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OpenPort(BaseModel):
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class NmapScanResult(ToolExecutionResult):
    host: str
    open_ports: List[OpenPort] = Field(default_factory=list)
    # Derived convenience flags, computed from open_ports - saves the agent
    # from re-parsing port numbers to decide what to investigate next.
    has_kerberos: bool = False              # port 88
    has_ldap: bool = False                  # port 389 or 3268
    has_smb: bool = False                   # port 445
    likely_domain_controller: bool = False  # kerberos + ldap + smb all present


class LDAPEnumerationResult(ToolExecutionResult):
    base_dn: Optional[str] = None
    entries: List[Dict[str, Any]] = Field(default_factory=list)
    entry_count: int = 0


class AdminCheckResult(ToolExecutionResult):
    target: str
    username: str
    is_admin: bool = False
    shares: List[str] = Field(default_factory=list)
