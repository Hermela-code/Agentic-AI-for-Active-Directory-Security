import uuid
from typing import Optional

from agent.analyzer import ADAnalyzer
from agent.config import MODEL_NAME
from agent.llm import OllamaReasoningEngine
from agent.models import (
    ApprovalRequest,
    ApprovalStatus,
    CapabilityTier,
    Finding,
    InvestigationState,
    ToolResult,
)
from tools.registry import ToolRegistry


class ADAgent:
    def __init__(self):
        self.model_name = MODEL_NAME
        self.tools = ToolRegistry()
        self.analyzer = ADAnalyzer()
        self.reasoning_engine = OllamaReasoningEngine(model_name=self.model_name)

    def request_human_approval(
        self, state: InvestigationState, capability: str, params: dict, rationale: str, risk_desc: str
    ) -> bool:
        """
        Human-in-the-Loop gate: presents complete context to the operator
        and enforces an explicit approval decision.
        """
        request = ApprovalRequest(
            id=f"appr-{uuid.uuid4().hex[:6]}",
            investigation_id=state.investigation_id,
            capability=capability,
            target=state.target,
            params=params,
            rationale=rationale,
            risk_assessment=risk_desc,
        )

        print("\n" + "!" * 60)
        print(" [!] HUMAN APPROVAL REQUIRED BEFORE EXECUTION")
        print("!" * 60)
        print(f" Request ID       : {request.id}")
        print(f" Proposed Action  : {request.capability}")
        print(f" Target           : {request.target}")
        print(f" Parameters       : {request.params}")
        print(f" Reason / Intent  : {request.rationale}")
        print(f" Risk Assessment  : {request.risk_assessment}")
        print("-" * 60)

        while True:
            response = input(" Proceed with execution? [A]pprove / [R]eject: ").strip().lower()
            if response in ("a", "approve"):
                request.status = ApprovalStatus.APPROVED
                state.approval_records.append(request)
                print(" [✓] Action APPROVED by operator.\n")
                return True
            elif response in ("r", "reject"):
                request.status = ApprovalStatus.REJECTED
                state.approval_records.append(request)
                print(" [✗] Action REJECTED by operator.\n")
                return False
            else:
                print(" Invalid input. Please enter 'A' to approve or 'R' to reject.")

    def run_capability(self, capability: str, target: str, **kwargs) -> ToolResult:
        """Executes an allowlisted security capability through the tool registry."""
        tool = self.tools.get_tool(capability)
        if tool is None:
            return ToolResult(
                tool=capability,
                target=target,
                status="failed",
                output=f"No tool registered for capability: {capability}",
            )
        return tool.run(target, **kwargs)

    def decide_next_action(self, state: InvestigationState) -> Optional[dict]:
        """Queries the LLM reasoning engine for the next action based on current state."""
        allowed = list(self.tools.tools.keys())
        decision = self.reasoning_engine.decide_action(state, allowed)

        if decision.investigation_complete or not decision.capability:
            return None

        return {
            "capability": decision.capability,
            "params": decision.params,
            "rationale": decision.rationale,
        }

    def investigate(self, target: str) -> InvestigationState:
        """Runs the autonomous Observe -> Analyze -> Decide -> Gate -> Act loop."""
        state = InvestigationState(
            investigation_id="inv-goad-001",
            target=target,
            status="running",
        )

        print(f"[*] Starting LLM-Guided Autonomous Investigation against: {target}")
        print(f"[*] Active Reasoning Model: {self.model_name}\n" + "=" * 60)

        while state.status == "running" and state.current_step < state.max_steps:
            state.current_step += 1
            print(f"\n--- [Cycle {state.current_step}] Observe & Decide (LLM) ---")

            # 1. DECIDE
            decision = self.decide_next_action(state)
            if not decision:
                print("[*] Investigation Complete: Model concluded no further actions required.")
                state.status = "completed"
                break

            capability = decision["capability"]
            params = decision["params"]
            rationale = decision["rationale"]

            print(f"[>] LLM Selected Capability: '{capability}'")
            print(f"[>] LLM Rationale: {rationale}")

            # 2. APPROVAL GATE CHECK
            tool_instance = self.tools.get_tool(capability)
            if tool_instance and tool_instance.tier == CapabilityTier.REQUIRES_APPROVAL:
                approved = self.request_human_approval(
                    state=state,
                    capability=capability,
                    params=params,
                    rationale=rationale,
                    risk_desc=tool_instance.risk_description,
                )
                if not approved:
                    state.decision_log.append(f"Step {state.current_step}: Blocked {capability} (Operator Rejected)")
                    print("[!] Execution aborted by human operator policy. Stopping or pivoting.")
                    state.status = "completed"
                    break

            state.decision_log.append(f"Step {state.current_step}: Ran {capability} - {rationale}")

            # 3. ACT
            print(f"[*] Executing capability '{capability}'...")
            result = self.run_capability(capability, state.target, **params)
            state.executed_capabilities.append(capability)

            # 4. ANALYZE & EXTRACT
            analysis = self.analyzer.analyze(result)
            print(f"[+] Output Status: {result.status}")
            print(f"[+] Summary: {analysis.summary}")

            # 5. UPDATE STATE
            for finding in analysis.findings:
                if not any(existing.title == finding.title for existing in state.findings):
                    state.findings.append(finding)
                    print(f"    - Finding: [{finding.severity.upper()}] {finding.title}")

                    if "Active Directory Domain Identified" in finding.title:
                        state.discovered_domain = finding.title.split(": ")[-1]
                    if "Domain Controller Hostname" in finding.title:
                        state.discovered_dc = finding.title.split(": ")[-1]

            print(f"[>] Analyzer Recommendation: {analysis.recommended_next_step}")

        return state


if __name__ == "__main__":
    agent = ADAgent()
    final_state = agent.investigate("192.168.56.11")

    print("\n" + "=" * 60)
    print("[*] Final Investigation Summary:")
    print(f"    - Status: {final_state.status}")
    print(f"    - Discovered Domain: {final_state.discovered_domain or 'Unknown'}")
    print(f"    - Discovered DC: {final_state.discovered_dc or 'Unknown'}")
    print(f"    - Executed Capabilities: {final_state.executed_capabilities}")
    print(f"    - Approvals Logged: {len(final_state.approval_records)}")
    print(f"    - Total Findings Recorded: {len(final_state.findings)}")