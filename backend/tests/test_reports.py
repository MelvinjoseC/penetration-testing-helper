import uuid
import json
import pytest
from fastapi import status
from app.models.engagement import Engagement, Scope
from app.models.scan import Scan, Finding

@pytest.fixture
def auth_header(client):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "report_tester@example.com",
            "password": "Password123!",
            "organization_name": "Report Security Org"
        }
    )
    login_res = client.post(
        "/api/v1/auth/login",
        data={"username": "report_tester@example.com", "password": "Password123!"}
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def sample_engagement_with_findings(client, db, auth_header):
    eng_res = client.post(
        "/api/v1/engagements",
        headers=auth_header,
        json={
            "name": "Audit Test <script>alert(1)</script>",
            "company": "Client Corp <img src=x onerror=alert(1)>",
            "authorization_reference": "Consent Ticket #888"
        }
    )
    eng_id = uuid.UUID(eng_res.json()["id"])
    engagement = db.query(Engagement).filter(Engagement.id == eng_id).first()

    # Add scope
    scope = Scope(
        engagement_id=eng_id,
        type="domain",
        pattern="*.target.com",
        is_excluded=False
    )
    db.add(scope)

    # Add scan
    scan = Scan(
        engagement_id=eng_id,
        target="https://target.com",
        profile="safe",
        status="completed"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Add finding with special characters
    finding = Finding(
        engagement_id=eng_id,
        scan_id=scan.id,
        title="Cross-Site Scripting <test>",
        severity="High",
        confidence="Confirmed",
        description="Vulnerable to XSS payload: <script>alert(1)</script>",
        scanner="core_orchestrator",
        fingerprint="test-fingerprint-12345"
    )
    db.add(finding)
    db.commit()

    return eng_id

def test_html_report_escaping(client, auth_header, sample_engagement_with_findings):
    eng_id = sample_engagement_with_findings
    res = client.post(
        f"/api/v1/reports?engagement_id={eng_id}&format=html",
        headers=auth_header
    )
    assert res.status_code == status.HTTP_200_OK
    assert "text/html" in res.headers["content-type"]
    content = res.text
    # Verify script tags are safely escaped in HTML output
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "&lt;img src=x onerror=alert(1)&gt;" in content

def test_json_report_export(client, auth_header, sample_engagement_with_findings):
    eng_id = sample_engagement_with_findings
    res = client.post(
        f"/api/v1/reports?engagement_id={eng_id}&format=json",
        headers=auth_header
    )
    assert res.status_code == status.HTTP_200_OK
    assert "application/json" in res.headers["content-type"]
    data = res.json()
    assert "engagement" in data
    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["severity_breakdown"]["High"] == 1
    assert data["findings"][0]["title"] == "Cross-Site Scripting <test>"

def test_markdown_report_export(client, auth_header, sample_engagement_with_findings):
    eng_id = sample_engagement_with_findings
    res = client.post(
        f"/api/v1/reports?engagement_id={eng_id}&format=markdown",
        headers=auth_header
    )
    assert res.status_code == status.HTTP_200_OK
    assert "text/markdown" in res.headers["content-type"]
    content = res.text
    assert "# Penetration Testing Assessment Report" in content
    assert "## 1. Executive Summary" in content
    assert "| High | 1 |" in content
    assert "### 1. Cross-Site Scripting <test> (High)" in content

def test_invalid_report_format(client, auth_header, sample_engagement_with_findings):
    eng_id = sample_engagement_with_findings
    res = client.post(
        f"/api/v1/reports?engagement_id={eng_id}&format=yaml",
        headers=auth_header
    )
    assert res.status_code == status.HTTP_400_BAD_REQUEST
