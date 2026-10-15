import pytest
from fastapi import status
from app.models.audit import AuditLog

@pytest.fixture
def auth_header(client):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "audit_user@example.com",
            "password": "Password123!",
            "organization_name": "Audit Test Corp"
        }
    )
    login_res = client.post(
        "/api/v1/auth/login",
        data={"username": "audit_user@example.com", "password": "Password123!"}
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_list_audit_logs(client, auth_header):
    # After register & login, audit logs should contain at least ORGANIZATION_CREATE, USER_REGISTER, USER_LOGIN
    res = client.get("/api/v1/audit-logs", headers=auth_header)
    assert res.status_code == status.HTTP_200_OK
    logs = res.json()
    assert len(logs) >= 3

    actions = [l["action"] for l in logs]
    assert "USER_LOGIN" in actions
    assert "USER_REGISTER" in actions

def test_filter_audit_logs_by_action(client, auth_header):
    res = client.get("/api/v1/audit-logs?action=USER_LOGIN", headers=auth_header)
    assert res.status_code == status.HTTP_200_OK
    logs = res.json()
    assert len(logs) >= 1
    assert all(l["action"] == "USER_LOGIN" for l in logs)

def test_audit_logs_pagination(client, auth_header):
    res = client.get("/api/v1/audit-logs?limit=1&skip=0", headers=auth_header)
    assert res.status_code == status.HTTP_200_OK
    assert len(res.json()) == 1
