from pydantic import BaseModel
from typing import Optional


class Investigation(BaseModel):
    id: str
    target: str
    status: str = "pending"


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
    findings: list[Finding] = []
    recommended_next_step: Optional[str] = None
    
class InvestigationState(BaseModel):
    investigation_id: str
    target: str
    status: str = "running"
    current_step: int = 0
    max_steps: int = 5

    # Accumulated Environment Knowledge
    discovered_dc: Optional[str] = None
    discovered_domain: Optional[str] = None
    executed_capabilities: list[str] = []
    
    # Findings and Decisions
    findings: list[Finding] = []
    decision_log: list[str] = []