from enum import Enum
from typing import List, Optional
from pydantic import BaseModel


class CapabilityTier(str, Enum):
    READ_ONLY = "read_only"
    REQUIRES_APPROVAL = "requires_approval"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ToolResult(BaseModel):
    tool: str
    target: str
    status: str
    output: str


class Finding(BaseModel):
    title: str
    severity: str
    description: str
    evidence: Optional[str] = None


class AnalysisResult(BaseModel):
    summary: str
    findings: List[Finding] = []
    recommended_next_step: Optional[str] = None


class AgentDecision(BaseModel):
    capability: Optional[str] = None
    params: dict = {}
    rationale: str
    investigation_complete: bool = False


# Define ApprovalRequest BEFORE InvestigationState
class ApprovalRequest(BaseModel):
    id: str
    investigation_id: str
    capability: str
    target: str
    params: dict = {}
    rationale: str
    risk_assessment: str
    status: ApprovalStatus = ApprovalStatus.PENDING


class InvestigationState(BaseModel):
    investigation_id: str
    target: str
    status: str = "running"
    current_step: int = 0
    max_steps: int = 5

    # Accumulated Environment Knowledge
    discovered_dc: Optional[str] = None
    discovered_domain: Optional[str] = None
    executed_capabilities: List[str] = []

    # Findings, Decisions, and Approvals
    findings: List[Finding] = []
    decision_log: List[str] = []
    approval_records: List[ApprovalRequest] = []