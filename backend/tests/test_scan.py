import pytest
from unittest.mock import patch
import uuid
from fastapi import status
from app.tasks.celery_app import celery_app
from app.models.engagement import Engagement, Scope, Asset
from app.models.scan import Scan, Finding

# Setup test fixtures for Celery eagerness
@pytest.fixture(autouse=True)
def celery_eager_mode():
    celery_app.conf.update(task_always_eager=True)
    yield
    celery_app.conf.update(task_always_eager=False)

def test_trigger_scan_pipeline_success(client, db):
    # 1. Create registration & authenticate
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "tester@domain.com",
            "password": "mypassword123",
            "organization_name": "Acme Pentest"
        }
    )
    login_res = client.post(
        "/api/v1/auth/login",
        data={"username": "tester@domain.com", "password": "mypassword123"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create Engagement
    eng_res = client.post(
        "/api/v1/engagements",
        headers=headers,
        json={
            "name": "Audit Staging Environment",
            "company": "Client Corp",
            "authorization_reference": "Consent Ticket #999"
        }
    )
    assert eng_res.status_code == status.HTTP_201_CREATED
    eng_id = uuid.UUID(eng_res.json()["id"])

    # 3. Add allowed Scope rule
    scope_res = client.post(
        f"/api/v1/engagements/{eng_id}/scope",
        headers=headers,
        json={
            "type": "domain",
            "pattern": "staging.mycompany.com",
            "is_excluded": False
        }
    )
    assert scope_res.status_code == status.HTTP_201_CREATED

    # Mock DNS and HTTP verification to bypass external requests
    with patch("app.api.engagements.verify_domain_dns", return_value=True):
        # 4. Verify Domain Ownership
        verify_res = client.post(
            f"/api/v1/engagements/{eng_id}/verify?domain=staging.mycompany.com",
            headers=headers,
            json={"method": "dns"}
        )
        assert verify_res.status_code == status.HTTP_200_OK
        assert verify_res.json()["is_verified"] is True

    # 5. Trigger Scan (Mocks out actual HTTP scan actions)
    mock_http_results = [
        {
            "check_type": "http_inspection",
            "status": "success",
            "evidence": {
                "url": "https://staging.mycompany.com",
                "status_code": 200,
                "headers": {
                    "Server": "Apache/2.4.41",
                    "X-Powered-By": "PHP/7.4.3",
                    "Set-Cookie": "session_id=xyz123; HttpOnly" # missing Secure
                }
            }
        }
    ]

    with patch("app.scanners.http_tls_scanner.HttpTlsScannerPlugin.execute", return_value=mock_http_results):
        scan_res = client.post(
            "/api/v1/scans",
            headers=headers,
            json={
                "engagement_id": str(eng_id),
                "target": "staging.mycompany.com",
                "profile": "safe"
            }
        )
        assert scan_res.status_code == status.HTTP_201_CREATED
        scan_id = scan_res.json()["id"]

    # Verify Scan completed in Eager Task Runner
    scan_db = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id)).first()
    assert scan_db.status == "completed"

    # Verify Asset was populated
    asset_db = db.query(Asset).filter(Asset.engagement_id == eng_id).first()
    assert asset_db is not None
    assert asset_db.value == "staging.mycompany.com"

    # Verify Findings were generated & populated
    findings = db.query(Finding).filter(Finding.engagement_id == eng_id).all()
    assert len(findings) > 0

    # We expect: Verbose Server, X-Powered-By, Missing CSP, Missing X-Frame-Options, Missing X-Content-Type-Options, Insecure Cookie
    titles = [f.title for f in findings]
    assert "Verbose Server Header Banner Disclosure" in titles
    assert "Information Disclosure: X-Powered-By Header Present" in titles
    assert "Missing Security Header: Content-Security-Policy" in titles
    assert "Insecure Cookie Configuration: session_id" in titles

    # 6. Generate Report
    report_res = client.post(
        f"/api/v1/reports?engagement_id={eng_id}",
        headers=headers
    )
    assert report_res.status_code == status.HTTP_200_OK
    assert b"Penetration Testing Assessment Report" in report_res.content
    assert b"Audit Staging Environment" in report_res.content
