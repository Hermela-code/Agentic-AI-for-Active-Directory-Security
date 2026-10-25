import threading
import uuid
import datetime
from typing import Dict, Optional
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import SessionLocal
from backend.models.orm import (
    InvestigationModel,
    FindingModel,
    ToolExecutionModel,
    ApprovalModel,
)
from agent.agent import ADAgent
from agent.models import InvestigationState, CapabilityTier, ApprovalStatus
# Import Recon tool and analyzer for Phase 1 recon
from tools.recon_tool import ReconTool
from agent.analyzer import ADAnalyzer


# Thread-safe dictionary to hold active approval event signals
active_approval_events: Dict[str, threading.Event] = {}
active_approval_decisions: Dict[str, bool] = {}


class InvestigationService:

    @staticmethod
    def start_investigation(target: str, scope: Optional[str] = None, metadata: Optional[Dict] = None) -> Optional[InvestigationModel]:
        """Validates scope, initializes database record with optional scope and metadata, and launches background thread."""
        # Previously validated against global authorized scopes; per‑request validation is now handled in the route.
        # Allow any target that passed the route validation.
        # if not settings.is_target_in_scope(target):
        #     return None

        db: Session = SessionLocal()
        inv_id = f"inv-{uuid.uuid4().hex[:8]}"

        inv = InvestigationModel(
            id=inv_id,
            target=target,
            scope=scope,
            investigation_metadata=metadata,
            status="running",
            current_step=0,
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)

        # ---- Phase 1: Passive reconnaissance ----
        # Execute ReconTool synchronously to gather AD service fingerprints.
        recon_tool = ReconTool()
        recon_result = recon_tool.run(target)
        # Persist the tool execution record.
        exec_record = ToolExecutionModel(
            investigation_id=inv_id,
            capability=recon_tool.name,
            target=target,
            status=recon_result.status,
            output_summary=recon_result.output[:500] if recon_result.output else "",
        )
        db.add(exec_record)
        # Analyze the recon output to generate findings and populate discovery fields.
        analyzer = ADAnalyzer()
        analysis = analyzer.analyze(recon_result)
        for f in analysis.findings:
            if not any(ef.title == f.title for ef in inv.findings):
                db_finding = FindingModel(
                    investigation_id=inv_id,
                    title=f.title,
                    severity=f.severity,
                    description=f.description,
                    evidence=f.evidence,
                )
                db.add(db_finding)
                # Capture domain / DC info if present in titles.
                if "Active Directory Domain Identified" in f.title:
                    inv.discovered_domain = f.title.split(": ")[-1]
                if "Domain Controller Hostname" in f.title:
                    inv.discovered_dc = f.title.split(": ")[-1]
        db.commit()

        db.close()

        # Run investigation worker in background thread
        worker = threading.Thread(
            target=InvestigationService._run_agent_worker,
            args=(inv_id, target),
            daemon=True
        )
        worker.start()

        return inv

    @staticmethod
    @staticmethod
    def _run_agent_worker(inv_id: str, target: str):
        """Worker loop executing the agent and persisting state/findings to the database."""
        db: Session = SessionLocal()
        agent = ADAgent()

        inv = db.query(InvestigationModel).filter(InvestigationModel.id == inv_id).first()
        if not inv:
            db.close()
            return

        state = InvestigationState(
            investigation_id=inv_id,
            target=target,
            status="running"
        )

        try:
            while state.status == "running" and state.current_step < state.max_steps:
                state.current_step += 1
                inv.current_step = state.current_step
                db.commit()

                # 1. LLM Decision
                decision = agent.decide_next_action(state)
                
                # STOP if LLM has no decision OR tries to repeat an already executed capability
                if not decision or decision.get("capability") in state.executed_capabilities:
                    inv.status = "completed"
                    inv.completed_at = datetime.datetime.utcnow()
                    db.commit()
                    break

                capability = decision["capability"]
                params = decision.get("params", {})
                rationale = decision.get("rationale", "")

                # 2. Check Approval Gate
                tool_instance = agent.tools.get_tool(capability)
                if tool_instance and tool_instance.tier == CapabilityTier.REQUIRES_APPROVAL:
                    appr_id = f"appr-{uuid.uuid4().hex[:6]}"
                    approval_record = ApprovalModel(
                        id=appr_id,
                        investigation_id=inv_id,
                        capability=capability,
                        target=target,
                        params=params,
                        rationale=rationale,
                        risk_assessment=tool_instance.risk_description,
                        status="pending"
                    )
                    db.add(approval_record)
                    inv.status = "awaiting_approval"
                    db.commit()

                    # Set up thread synchronization event
                    event = threading.Event()
                    active_approval_events[appr_id] = event

                    # Wait up to 5 minutes for approval via API
                    signaled = event.wait(timeout=300)
                    approved = active_approval_decisions.get(appr_id, False)

                    # Clean up signal state
                    active_approval_events.pop(appr_id, None)
                    active_approval_decisions.pop(appr_id, None)

                    if not signaled or not approved:
                        inv.status = "completed"
                        inv.completed_at = datetime.datetime.utcnow()
                        db.commit()
                        break
                    else:
                        inv.status = "running"
                        db.commit()

                # 3. Execution
                result = agent.run_capability(capability, target, **params)
                state.executed_capabilities.append(capability)

                # Persist tool execution
                exec_record = ToolExecutionModel(
                    investigation_id=inv_id,
                    capability=capability,
                    target=target,
                    status=result.status,
                    output_summary=result.output[:500] if result.output else ""
                )
                db.add(exec_record)

                # 4. Analysis & Finding Persistence
                analysis = agent.analyzer.analyze(result)
                for f in analysis.findings:
                    if not any(ef.title == f.title for ef in state.findings):
                        state.findings.append(f)
                        db_finding = FindingModel(
                            investigation_id=inv_id,
                            title=f.title,
                            severity=f.severity,
                            description=f.description,
                            evidence=f.evidence
                        )
                        db.add(db_finding)

                        if "Active Directory Domain Identified" in f.title:
                            inv.discovered_domain = f.title.split(": ")[-1]
                        if "Domain Controller Hostname" in f.title:
                            inv.discovered_dc = f.title.split(": ")[-1]

                db.commit()

                # If domain enumeration completed and anonymous bind is restricted, stop the loop
                if capability == "domain_enumeration":
                    inv.status = "completed"
                    inv.completed_at = datetime.datetime.utcnow()
                    db.commit()
                    break

            if inv.status != "awaiting_approval":
                inv.status = "completed"
                inv.completed_at = datetime.datetime.utcnow()
                db.commit()

        except Exception as e:
            inv.status = "failed"
            inv.completed_at = datetime.datetime.utcnow()
            db.commit()
        finally:
            db.close()