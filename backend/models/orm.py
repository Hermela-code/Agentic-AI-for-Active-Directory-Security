import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.database import Base


class InvestigationModel(Base):
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True, index=True)
    target = Column(String(64), nullable=False)
    scope = Column(String(64), nullable=True)  # Authorized CIDR scope provided by UI
    investigation_metadata = Column(JSON, nullable=True)   # Optional investigation metadata
    status = Column(String(32), default="pending", index=True)
    current_step = Column(Integer, default=0)
    discovered_domain = Column(String(128), nullable=True)
    discovered_dc = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    findings = relationship("FindingModel", back_populates="investigation", cascade="all, delete-orphan")
    tool_executions = relationship("ToolExecutionModel", back_populates="investigation", cascade="all, delete-orphan")
    approvals = relationship("ApprovalModel", back_populates="investigation", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    severity = Column(String(32), default="info")
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    investigation = relationship("InvestigationModel", back_populates="findings")


class ToolExecutionModel(Base):
    __tablename__ = "tool_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False, index=True)
    capability = Column(String(64), nullable=False)
    target = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False)
    output_summary = Column(Text, nullable=True)
    executed_at = Column(DateTime, default=datetime.datetime.utcnow)

    investigation = relationship("InvestigationModel", back_populates="tool_executions")


class ApprovalModel(Base):
    __tablename__ = "approvals"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id"), nullable=False, index=True)
    capability = Column(String(64), nullable=False)
    target = Column(String(64), nullable=False)
    params = Column(JSON, default=dict)
    rationale = Column(Text, nullable=False)
    risk_assessment = Column(Text, nullable=False)
    status = Column(String(32), default="pending", index=True)  # pending, approved, rejected
    requested_at = Column(DateTime, default=datetime.datetime.utcnow)
    decided_at = Column(DateTime, nullable=True)

    investigation = relationship("InvestigationModel", back_populates="approvals")
