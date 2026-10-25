import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.orm import ApprovalModel
from backend.schemas.api_schemas import ApprovalResponse
from backend.services.investigation_service import (
    active_approval_events,
    active_approval_decisions,
)

router = APIRouter(prefix="/approvals", tags=["Human Approvals"])


@router.get("/pending", response_model=List[ApprovalResponse])
def get_pending_approvals(db: Session = Depends(get_db)):
    return db.query(ApprovalModel).filter(ApprovalModel.status == "pending").all()


@router.post("/{appr_id}/approve", response_model=ApprovalResponse)
def approve_action(appr_id: str, db: Session = Depends(get_db)):
    record = db.query(ApprovalModel).filter(ApprovalModel.id == appr_id).first()
    if not record or record.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending approval not found.",
        )

    record.status = "approved"
    record.decided_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(record)

    # Record decision and wake the waiting background worker
    active_approval_decisions[appr_id] = True
    if appr_id in active_approval_events:
        active_approval_events[appr_id].set()

    return record


@router.post("/{appr_id}/reject", response_model=ApprovalResponse)
def reject_action(appr_id: str, db: Session = Depends(get_db)):
    record = db.query(ApprovalModel).filter(ApprovalModel.id == appr_id).first()
    if not record or record.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending approval not found.",
        )

    record.status = "rejected"
    record.decided_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(record)

    # Record rejection and wake the waiting background worker to terminate cleanly
    active_approval_decisions[appr_id] = False
    if appr_id in active_approval_events:
        active_approval_events[appr_id].set()

    return record