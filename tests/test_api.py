from backend.models.orm import ApprovalModel, InvestigationModel


def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["authorized_scope"] == "192.168.56.0/24"


def test_target_out_of_scope_rejected(client):
    # Public IP outside the authorized 192.168.56.0/24 boundary
    response = client.post(
        "/api/investigations",
        json={"target": "8.8.8.8"}
    )
    assert response.status_code == 400
    assert "out of authorized scope" in response.json()["detail"]


def test_start_investigation_success(client, monkeypatch):
    # Mock the background worker thread so unit tests don't run network scans
    from backend.services.investigation_service import InvestigationService
    monkeypatch.setattr(InvestigationService, "_run_agent_worker", lambda inv_id, target: None)

    response = client.post(
        "/api/investigations",
        json={"target": "192.168.56.11"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["target"] == "192.168.56.11"
    assert data["status"] == "running"
    assert data["id"].startswith("inv-")


def test_approval_lifecycle(client, db_session):
    # Seed an investigation and a pending approval directly into the test database
    inv = InvestigationModel(id="inv-test-01", target="192.168.56.11", status="awaiting_approval")
    appr = ApprovalModel(
        id="appr-test-01",
        investigation_id="inv-test-01",
        capability="domain_enumeration",
        target="192.168.56.11",
        rationale="LDAP open",
        risk_assessment="Read queries",
        status="pending"
    )
    db_session.add(inv)
    db_session.add(appr)
    db_session.commit()

    # Verify it appears in pending approvals
    pending_resp = client.get("/api/approvals/pending")
    assert pending_resp.status_code == 200
    pending_data = pending_resp.json()
    assert len(pending_data) == 1
    assert pending_data[0]["id"] == "appr-test-01"

    # Approve the action
    approve_resp = client.post("/api/approvals/appr-test-01/approve")
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"
    assert approve_resp.json()["decided_at"] is not None

    # Confirm it no longer shows up in pending
    pending_after = client.get("/api/approvals/pending")
    assert len(pending_after.json()) == 0
