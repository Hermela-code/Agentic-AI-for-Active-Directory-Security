from tools.domain_enum_tool import DomainEnumerationTool
from tools.nmap_tool import NmapTool

class ToolRegistry:
    def __init__(self):
        self.tools = {
            "network_discovery": NmapTool(),
            "domain_enumeration": DomainEnumerationTool(),
        }

    def get_tool(self, capability: str):
        return self.tools.get(capability)