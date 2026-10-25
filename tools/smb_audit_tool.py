"""Low‑impact SMB anonymous audit.

The tool attempts to enumerate SMB shares on the target without
credentials. It uses the existing ``netexec_wrapper.smb_enum`` helper,
which performs an unauthenticated ``smbclient`` style request. The
result is wrapped in a ``ToolResult`` compatible with the agent.
"""

import json
from typing import Optional

from agent.models import CapabilityTier, ToolResult
from tools.base import SecurityTool
from tools import netexec_wrapper


class SMBAnonymousAuditTool(SecurityTool):
    """Enumerates readable SMB shares via a null session.

    * Tier: READ_ONLY – no credentials are required.
    * Risk: Very low – only attempts to list shares.
    """

    name = "smb_anonymous_audit"
    tier = CapabilityTier.READ_ONLY
    risk_description = (
        "Attempts unauthenticated SMB share enumeration. No credential "
        "information is sent; only read‑only share names are queried."
    )

    def run(self, target: str, **kwargs) -> ToolResult:
        # Reuse the netexec_wrapper logic which already performs an SMB
        # enumeration without credentials.
        result = netexec_wrapper.smb_enum(target)
        # Normalise output to JSON for the analyzer.
        output = json.dumps({
            "status": result.status,
            "shares": result.shares or [],
            "error": result.error or "",
        })
        return ToolResult(
            tool=self.name,
            target=target,
            status=result.status,
            output=output,
        )
