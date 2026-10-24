from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
import ipaddress
import socket
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.orm import (
    InvestigationModel,
    FindingModel,
    ToolExecutionModel,
    ApprovalModel,
)
from backend.schemas.api_schemas import (
    StartInvestigationRequest,
    InvestigationResponse,
    FindingResponse,
    ToolExecutionResponse,
    ApprovalResponse,
)
from backend.services.investigation_service import InvestigationService
from backend.config import settings

router = APIRouter(prefix="/investigations", tags=["Investigations"])

@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
def start_investigation(req: StartInvestigationRequest):
    # Validate that the target IP/hostname lies within the user‑provided CIDR scope.
    try:
        # Resolve hostname to IP if necessary.
        try:
            resolved_ip = socket.gethostbyname(req.target.strip())
        except Exception:
            resolved_ip = req.target.strip()
        target_ip = ipaddress.ip_address(resolved_ip)
        scope_network = ipaddress.ip_network(req.scope.strip(), strict=False)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target or scope: {exc}"
        )
    if target_ip not in scope_network:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target {req.target} is out of authorized scope ({req.scope})."
        )
    inv = InvestigationService.start_investigation(req.target, req.scope, req.metadata)
    return inv

@router.get("", response_model=List[InvestigationResponse])
def list_investigations(db: Session = Depends(get_db)):
    return db.query(InvestigationModel).order_by(InvestigationModel.created_at.desc()).all()

@router.get("/{inv_id}", response_model=InvestigationResponse)
def get_investigation(inv_id: str, db: Session = Depends(get_db)):
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found.")
    return inv

@router.get("/{inv_id}/findings", response_model=List[FindingResponse])
def get_findings(inv_id: str, db: Session = Depends(get_db)):
    return db.query(FindingModel).filter(FindingModel.investigation_id == inv_id).all()

@router.get("/{inv_id}/executions", response_model=List[ToolExecutionResponse])
def get_executions(inv_id: str, db: Session = Depends(get_db)):
    return db.query(ToolExecutionModel).filter(ToolExecutionModel.investigation_id == inv_id).all()

@router.get("/{inv_id}/approvals", response_model=List[ApprovalResponse])
def get_approvals(inv_id: str, db: Session = Depends(get_db)):
    return db.query(ApprovalModel).filter(ApprovalModel.investigation_id == inv_id).all()