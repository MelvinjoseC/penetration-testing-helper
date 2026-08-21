from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.auth import router as auth_router
from app.api.engagements import router as engagements_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.reports import router as reports_router

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-seed default developer credentials for easy testing
    from app.core.database import SessionLocal
    from app.models.user import User, Organization
    from app.auth.security import get_password_hash
    
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.email == "admin@local.test").first():
            org = db.query(Organization).filter(Organization.name == "Local Dev Corp").first()
            if not org:
                org = Organization(name="Local Dev Corp")
                db.add(org)
                db.commit()
                db.refresh(org)
            
            hashed_pwd = get_password_hash("Password123!")
            user = User(
                email="admin@local.test",
                hashed_password=hashed_pwd,
                role="admin",
                organization_id=org.id,
                is_active=True
            )
            db.add(user)
            db.commit()
    except Exception as e:
        print("Database startup seed failed:", e)
    finally:
        db.close()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(engagements_router, prefix=settings.API_V1_STR)
app.include_router(scans_router, prefix=settings.API_V1_STR)
app.include_router(findings_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)

@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "project": settings.PROJECT_NAME}
