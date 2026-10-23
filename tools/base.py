from abc import ABC, abstractmethod
from agent.models import CapabilityTier, ToolResult


class SecurityTool(ABC):
    """
    Base contract for every registered security capability.

    agent.py calls: tool.run(target, **kwargs) -> ToolResult
    agent.py reads: tool.tier, tool.risk_description
    (see ADAgent.run_capability and ADAgent.investigate in agent/agent.py)
    """

    name: str = "unnamed_tool"
    tier: CapabilityTier = CapabilityTier.READ_ONLY
    risk_description: str = "No risk description provided."

    @abstractmethod
    def run(self, target: str, **kwargs) -> ToolResult:
        raise NotImplementedError
