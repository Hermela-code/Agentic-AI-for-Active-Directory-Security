import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# Request to start an investigation
class StartInvestigationRequest(BaseModel):
    target: str = Field(..., example="192.168.56.11", description="Target IP or hostname inside authorized scope")
    scope: str = Field(..., example="192.168.56.0/24", description="Authorized CIDR scope for the investigation")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional investigation metadata")


# Response when investigation is created
class InvestigationResponse(BaseModel):
    id: str
    target: str
    scope: Optional[str] = None
    status: str
    current_step: int
    discovered_domain: Optional[str] = None
    discovered_dc: Optional[str] = None
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True


# Finding schema
class FindingResponse(BaseModel):
    id: int
    investigation_id: str
    title: str
    severity: str
    description: str
    evidence: Optional[str] = None
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# Tool Execution schema
class ToolExecutionResponse(BaseModel):
    id: int
    investigation_id: str
    capability: str
    target: str
    status: str
    output_summary: Optional[str] = None
    executed_at: datetime.datetime

    class Config:
        from_attributes = True


# Approval schema
class ApprovalResponse(BaseModel):
    id: str
    investigation_id: str
    capability: str
    target: str
    params: Dict[str, Any] = {}
    rationale: str
    risk_assessment: str
    status: str
    requested_at: datetime.datetime
    decided_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True
