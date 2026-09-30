from agent.config import MODEL_NAME
from agent.models import Investigation, ToolResult
from agent.analyzer import ADAnalyzer
from tools.registry import ToolRegistry


class ADAgent:
    def __init__(self):
        self.model_name = MODEL_NAME
        self.tools = ToolRegistry()
        self.analyzer = ADAnalyzer()

    def start_investigation(self, target: str) -> Investigation:
        investigation = Investigation(
            id="investigation-001",
            target=target,
            status="running"
        )

        print(f"Starting investigation against: {target}")
        print(f"AI model: {self.model_name}")

        return investigation

    def run_capability(self, capability: str, target: str) -> ToolResult:
        tool = self.tools.get_tool(capability)

        if tool is None:
            return ToolResult(
                tool=capability,
                target=target,
                status="failed",
                output=f"No tool is registered for capability: {capability}"
            )

        return tool.run(target)


if __name__ == "__main__":
    agent = ADAgent()

    investigation = agent.start_investigation("192.168.56.11")
    print(investigation)

    result = agent.run_capability(
        capability="network_discovery",
        target="192.168.56.11"
    )

    print(result)

    analysis = agent.analyzer.analyze(result)

    print("\nAgent Analysis:")
    print(f"Summary: {analysis.summary}")

    for finding in analysis.findings:
        print(f"\nFinding: {finding.title}")
        print(f"Severity: {finding.severity}")
        print(f"Description: {finding.description}")
        print(f"Evidence: {finding.evidence}")

    print(f"\nRecommended next step:")
    print(analysis.recommended_next_step)