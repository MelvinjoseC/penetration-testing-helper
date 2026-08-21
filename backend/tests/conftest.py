import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import Base, get_db
from app.models import User, Organization, AuditLog


# Use an isolated in-memory SQLite database for test execution
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function", autouse=True)
def setup_database():
    # Setup tables before each test case
    Base.metadata.create_all(bind=engine)
    yield
    # Drop tables after each test case
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def db() -> Generator:
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture(scope="function")
def client(db) -> Generator:
    def override_get_db():
        try:
            yield db
        finally:
            pass
            
    # Apply dependency injection override
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

from unittest.mock import patch

@pytest.fixture(scope="function", autouse=True)
def patch_scan_task_db(db):
    """
    Automatically mock SessionLocal inside scan_task.py to use the active SQLite test database session.
    Also bypasses db.close() to prevent detaching active FastAPI request instances in eager mode.
    """
    orig_close = db.close
    db.close = lambda: None
    with patch("app.tasks.scan_task.SessionLocal", return_value=db):
        yield
    db.close = orig_close

