import uuid
import pytest
from fastapi import status
from app.models.engagement import Engagement
from app.models.scan import Scan, Finding
from app.models.audit import AuditLog

@pytest.fixture
def auth_header(client):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "triage_tester@example.com",
            "password": "Password123!",
            "organization_name": "Triage Org"
        }
    )
    login_res = client.post(
        "/api/v1/auth/login",
        data={"username": "triage_tester@example.com", "password": "Password123!"}
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def finding_setup(client, db, auth_header):
    eng_res = client.post(
        "/api/v1/engagements",
        headers=auth_header,
        json={
            "name": "Finding Test Engagement",
            "company": "Triage Corp",
            "authorization_reference": "Ref #101"
        }
    )
    eng_id = uuid.UUID(eng_res.json()["id"])

    scan = Scan(
        engagement_id=eng_id,
        target="https://triage.target.com",
        profile="safe",
        status="completed"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    finding = Finding(
        engagement_id=eng_id,
        scan_id=scan.id,
        title="Missing Content-Security-Policy",
        severity="Medium",
        confidence="Confirmed",
        description="Missing CSP header.",
        scanner="http_tls_scanner",
        status="New",
        fingerprint="triage-fp-001"
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding.id

def test_list_findings_filter(client, auth_header, finding_setup):
    res = client.get("/api/v1/findings?severity=Medium", headers=auth_header)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert len(data) >= 1
    assert data[0]["severity"] == "Medium"

    # Filter with non-matching severity
    res_empty = client.get("/api/v1/findings?severity=Critical", headers=auth_header)
    assert res_empty.status_code == status.HTTP_200_OK
    assert len(res_empty.json()) == 0

def test_update_finding_triage(client, db, auth_header, finding_setup):
    finding_id = finding_setup
    patch_res = client.patch(
        f"/api/v1/findings/{finding_id}",
        headers=auth_header,
        json={
            "status": "Confirmed",
            "severity": "High",
            "remediation": "Add CSP header with strict nonces."
        }
    )
    assert patch_res.status_code == status.HTTP_200_OK
    updated = patch_res.json()
    assert updated["status"] == "Confirmed"
    assert updated["severity"] == "High"
    assert updated["remediation"] == "Add CSP header with strict nonces."

    # Verify audit log recorded the triage event
    log = db.query(AuditLog).filter(
        AuditLog.action == "FINDING_TRIAGE",
        AuditLog.target == str(finding_id)
    ).first()
    assert log is not None
    assert log.details["new_status"] == "Confirmed"
    assert log.details["new_severity"] == "High"

def test_update_finding_invalid_status(client, auth_header, finding_setup):
    finding_id = finding_setup
    res = client.patch(
        f"/api/v1/findings/{finding_id}",
        headers=auth_header,
        json={"status": "NonExistentStatus"}
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
