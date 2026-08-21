from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

# For development, check if we use postgres or sqlite. We'll use settings.DATABASE_URL
# If sqlite is used (e.g. in tests), configure check_same_thread as False.
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

from app.models.base import Base


def get_db() -> Generator:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()
