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

investigation = Investigation(
    id="test-001",
    target="192.168.56.10"
)

