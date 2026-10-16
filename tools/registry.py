from tools.base import SecurityTool
from tools.domain_enumeration import DomainEnumerationTool
from tools.network_discovery import NetworkDiscoveryTool


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
        self.register(NetworkDiscoveryTool())
        self.register(DomainEnumerationTool())

    def register(self, tool: SecurityTool) -> None:
        self.tools[tool.name] = tool

    def get_tool(self, capability: str) -> SecurityTool | None:
        return self.tools.get(capability)
