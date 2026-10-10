from typing import Optional
from agent.analyzer import ADAnalyzer
from agent.config import MODEL_NAME
from agent.models import Finding, InvestigationState, ToolResult
from tools.registry import ToolRegistry


class ADAgent:
    def __init__(self):
        self.model_name = MODEL_NAME
        self.tools = ToolRegistry()
        self.analyzer = ADAnalyzer()

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
        """
        Deterministic decision policy based on current investigation state.
        Determines the next capability based on identified knowledge gaps.
        """
        # Step 1: If we haven't done initial network discovery, run it first
        if "network_discovery" not in state.executed_capabilities:
            return {
                "capability": "network_discovery",
                "params": {},
                "rationale": "Initial reconnaissance required to identify exposed ports and services.",
            }

        # Step 2: If network discovery revealed AD indicators but domain isn't fully profiled, run domain_enum
        has_ad_indicator = any("Kerberos" in f.title or "LDAP" in f.title for f in state.findings)
        if has_ad_indicator and "domain_enumeration" not in state.executed_capabilities:
            return {
                "capability": "domain_enumeration",
                "params": {"operation": "users"},
                "rationale": "Active Directory indicators observed. Querying directory services for domain hierarchy and policies.",
            }

        # Step 3: Stop when baseline reconnaissance is satisfied or credentials are required
        return None

    def investigate(self, target: str) -> InvestigationState:
        """Runs the autonomous Observe -> Analyze -> Decide -> Act loop."""
        state = InvestigationState(
            investigation_id="inv-goad-001",
            target=target,
            status="running",
        )

        print(f"[*] Starting Autonomous Investigation against target: {target}")
        print(f"[*] Active Reasoning Model Profile: {self.model_name}\n" + "=" * 60)

        while state.status == "running" and state.current_step < state.max_steps:
            state.current_step += 1
            print(f"\n--- [Cycle {state.current_step}] Observe & Decide ---")

            # 1. DECIDE
            decision = self.decide_next_action(state)
            if not decision:
                print("[*] Investigation Complete: No further safe reconnaissance actions queued.")
                state.status = "completed"
                break

            capability = decision["capability"]
            params = decision["params"]
            rationale = decision["rationale"]

            print(f"[>] Selected Capability: '{capability}'")
            print(f"[>] Rationale: {rationale}")
            state.decision_log.append(f"Step {state.current_step}: Ran {capability} - {rationale}")

            # 2. ACT
            print(f"[*] Executing capability '{capability}'...")
            result = self.run_capability(capability, state.target, **params)
            state.executed_capabilities.append(capability)

            # 3. ANALYZE & EXTRACT
            analysis = self.analyzer.analyze(result)
            print(f"[+] Output Status: {result.status}")
            print(f"[+] Summary: {analysis.summary}")

            # 4. UPDATE STATE
            for finding in analysis.findings:
                # Deduplicate findings by title
                if not any(existing.title == finding.title for existing in state.findings):
                    state.findings.append(finding)
                    print(f"    - Finding: [{finding.severity.upper()}] {finding.title}")

                    # Extract entity metadata into state
                    if "Active Directory Domain Identified" in finding.title:
                        state.discovered_domain = finding.title.split(": ")[-1]
                    if "Domain Controller Hostname" in finding.title:
                        state.discovered_dc = finding.title.split(": ")[-1]

            print(f"[>] Recommendation: {analysis.recommended_next_step}")

        return state


if __name__ == "__main__":
    agent = ADAgent()
    final_state = agent.investigate("192.168.56.11")

    print("\n" + "=" * 60)
    print("[*] Final Investigation Summary:")
    print(f"    - Status: {final_state.status}")
    print(f"    - Target Domain: {final_state.discovered_domain or 'Unknown'}")
    print(f"    - Target DC: {final_state.discovered_dc or 'Unknown'}")
    print(f"    - Executed Capabilities: {final_state.executed_capabilities}")
    print(f"    - Total Findings Recorded: {len(final_state.findings)}")