from tools.base import SecurityTool
from tools.capabilities import (
    ADUserEnumerationCapability,
    CheckAdminAccessCapability,
    DomainEnumerationCapability,
    NetworkDiscoveryCapability,
)


class ToolRegistry:
    """
    Central registry of allowlisted security capabilities.

    agent.py uses this as:
        self.tools = ToolRegistry()
        self.tools.get_tool(capability)      # -> SecurityTool | None
        list(self.tools.tools.keys())        # -> allowed capability names
    """

    def __init__(self):
        self.tools: dict[str, SecurityTool] = {}
        self._register_defaults()

    def _register_defaults(self):
        self.register(NetworkDiscoveryCapability())
        self.register(DomainEnumerationCapability())
        self.register(ADUserEnumerationCapability())
        self.register(CheckAdminAccessCapability())
        # Register SMB anonymous audit capability
        from tools.smb_audit_tool import SMBAnonymousAuditTool
        self.register(SMBAnonymousAuditTool())

    def register(self, tool: SecurityTool) -> None:
        self.tools[tool.name] = tool

    def get_tool(self, capability: str) -> SecurityTool | None:
        return self.tools.get(capability)
