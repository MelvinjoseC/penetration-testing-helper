import pytest
from fastapi import status
from sqlalchemy.orm import Session
from app.models.user import User, Organization
from app.models.audit import AuditLog

def test_register_user(client, db: Session):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "tester@example.com",
            "password": "securepassword123",
            "organization_name": "Acme Security Corp"
        }
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == "tester@example.com"
    assert data["role"] == "admin"
    assert "id" in data
    assert "organization_id" in data

    # Verify Organization was created
    org = db.query(Organization).filter(Organization.name == "Acme Security Corp").first()
    assert org is not None
    assert str(org.id) == data["organization_id"]

    # Verify User was created
    user = db.query(User).filter(User.email == "tester@example.com").first()
    assert user is not None
    assert user.role == "admin"
    
    # Verify Audit Logs were created
    audit_org_create = db.query(AuditLog).filter(AuditLog.action == "ORGANIZATION_CREATE").first()
    assert audit_org_create is not None
    assert audit_org_create.organization_id == org.id

    audit_user_reg = db.query(AuditLog).filter(AuditLog.action == "USER_REGISTER").first()
    assert audit_user_reg is not None
    assert audit_user_reg.user_id == user.id

def test_register_duplicate_email(client):
    payload = {
        "email": "duplicate@example.com",
        "password": "securepassword123",
        "organization_name": "First Org"
    }
    response1 = client.post("/api/v1/auth/register", json=payload)
    assert response1.status_code == status.HTTP_201_CREATED

    response2 = client.post("/api/v1/auth/register", json=payload)
    assert response2.status_code == status.HTTP_400_BAD_REQUEST
    assert "already exists" in response2.json()["detail"]

def test_login_success(client, db: Session):
    # Register a user first
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "user@example.com",
            "password": "mypassword123",
            "organization_name": "Test Org"
        }
    )

    # Login
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "user@example.com",
            "password": "mypassword123"
        }
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Verify login audit log
    user = db.query(User).filter(User.email == "user@example.com").first()
    login_log = db.query(AuditLog).filter(
        AuditLog.user_id == user.id,
        AuditLog.action == "USER_LOGIN"
    ).first()
    assert login_log is not None

def test_login_invalid_credentials(client):
    # Try logging in with non-existent user
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "nonexistent@example.com",
            "password": "password"
        }
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Incorrect email or password" in response.json()["detail"]

def test_read_user_me(client):
    # Register & Login
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "me@example.com",
            "password": "secretpassword",
            "organization_name": "Me Corp"
        }
    )
    login_response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "me@example.com",
            "password": "secretpassword"
        }
    )
    token = login_response.json()["access_token"]

    # Get Profile with valid token
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["email"] == "me@example.com"
    assert data["organization"]["name"] == "Me Corp"

def test_read_user_me_unauthorized(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_tenant_isolation(client):
    # Register Tenant A
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@tenant-a.com",
            "password": "tenantApassword",
            "organization_name": "Tenant A Corp"
        }
    )
    # Register Tenant B
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@tenant-b.com",
            "password": "tenantBpassword",
            "organization_name": "Tenant B Corp"
        }
    )

    # Login to A
    login_a = client.post(
        "/api/v1/auth/login",
        data={"username": "admin@tenant-a.com", "password": "tenantApassword"}
    )
    token_a = login_a.json()["access_token"]

    # Login to B
    login_b = client.post(
        "/api/v1/auth/login",
        data={"username": "admin@tenant-b.com", "password": "tenantBpassword"}
    )
    token_b = login_b.json()["access_token"]

    # Get A profile
    res_a = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_a}"})
    data_a = res_a.json()

    # Get B profile
    res_b = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_b}"})
    data_b = res_b.json()

    # Assert tenants are different and isolated
    assert data_a["organization_id"] != data_b["organization_id"]
    assert data_a["organization"]["name"] == "Tenant A Corp"
    assert data_b["organization"]["name"] == "Tenant B Corp"
