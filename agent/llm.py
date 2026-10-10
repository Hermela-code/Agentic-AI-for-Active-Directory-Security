import json
import urllib.request
import urllib.error
from typing import Optional
from agent.config import MODEL_NAME
from agent.models import AgentDecision, InvestigationState


class OllamaReasoningEngine:
    """Interfaces with a local Ollama instance for structured agent decision-making."""

    def __init__(self, model_name: str = MODEL_NAME, endpoint: str = "http://localhost:11434/api/chat"):
        self.model_name = model_name
        self.endpoint = endpoint

    def decide_action(
        self, state: InvestigationState, available_capabilities: list[str]
    ) -> AgentDecision:
        """Prompts the LLM with the current investigation state and parses its structured decision."""

        system_prompt = (
            "You are an Active Directory security investigation agent operating in a controlled lab.\n"
            "Your task is to analyze the current investigation findings and select the NEXT safe capability.\n\n"
            f"Allowed capabilities strictly limited to: {available_capabilities}\n\n"
            "Decision Rules:\n"
            "1. Only choose a capability from the allowed list that has NOT already been executed, unless re-checking is justified.\n"
            "2. If initial network discovery has not been performed, execute 'network_discovery' first.\n"
            "3. If directory indicators (Kerberos/LDAP) were found and LDAP enumeration has not run, choose 'domain_enumeration'.\n"
            "4. If directory queries require authentication or no safe non-credential capabilities remain, set 'investigation_complete' to true.\n"
            "5. Respond ONLY with a valid JSON object matching the requested schema. No markdown formatting, no explanation outside JSON.\n\n"
            "JSON Schema:\n"
            "{\n"
            '  "capability": "<name_or_null>",\n'
            '  "params": {},\n'
            '  "rationale": "<concise technical justification>",\n'
            '  "investigation_complete": false\n'
            "}"
        )

        user_content = {
            "target": state.target,
            "current_step": state.current_step,
            "executed_capabilities": state.executed_capabilities,
            "discovered_domain": state.discovered_domain,
            "discovered_dc": state.discovered_dc,
            "findings_summary": [
                {"title": f.title, "severity": f.severity, "evidence": f.evidence}
                for f in state.findings
            ],
        }

        payload = {
            "model": self.model_name,
            "format": "json",
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_content)},
            ],
            "options": {
                "temperature": 0.1,  # Low temperature to minimize randomness
            },
        }

        try:
            req = urllib.request.Request(
                self.endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=60) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                raw_response = res_data.get("message", {}).get("content", "{}")

            parsed_data = json.loads(raw_response)
            decision = AgentDecision(**parsed_data)

            # Safety enforcement: verify capability is in allowlist
            if (
                decision.capability
                and decision.capability not in available_capabilities
            ):
                return AgentDecision(
                    capability=None,
                    params={},
                    rationale=f"LLM proposed unauthorized capability '{decision.capability}'. Aborting.",
                    investigation_complete=True,
                )

            return decision

        except (urllib.error.URLError, json.JSONDecodeError, Exception) as e:
            # Resilient fallback: report failure rather than crashing
            return AgentDecision(
                capability=None,
                params={},
                rationale=f"LLM reasoning error or connection failure: {str(e)}",
                investigation_complete=True,
            )
