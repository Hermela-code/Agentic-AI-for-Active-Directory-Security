from abc import ABC, abstractmethod

from agent.models import ToolResult


class SecurityTool(ABC):
    """
    Base interface for security tools used by the agent.
    """

    name: str

    @abstractmethod
    def run(self, target: str) -> ToolResult:
        """
        Run the tool against an authorized target.
        """
        pass
