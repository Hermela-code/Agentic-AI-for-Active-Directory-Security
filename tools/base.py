from abc import ABC, abstractmethod
from agent.models import CapabilityTier, ToolResult


class SecurityTool(ABC):
    """Base interface for security tools used by the agent."""

    name: str
    tier: CapabilityTier = CapabilityTier.READ_ONLY
    risk_description: str = "Passive observation; low operational risk."

    @abstractmethod
    def run(self, target: str, **kwargs) -> ToolResult:
        """Run the tool against an authorized target."""
        pass