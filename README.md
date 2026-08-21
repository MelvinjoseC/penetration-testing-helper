# AI-Assisted Penetration Testing Orchestration Platform

An enterprise-grade, multi-tenant AI-assisted orchestration platform for authorized penetration testing. Built with a FastAPI backend, Celery/Dramatiq task worker integration, and a React frontend.

---

## Technical Stack
- **Backend**: FastAPI, Pydantic, SQLAlchemy, Alembic
- **Database**: PostgreSQL (Production) / SQLite (Testing/Local fallback)
- **Background Queue**: Redis + Celery/Dramatiq (Phase 3)
- **Frontend**: React, Vite, Tailwind CSS, TypeScript (Phase 2+)

---

## Directory Structure

```text
pentest-platform/
├── backend/
│   ├── app/
│   │   ├── api/          # Route handlers (auth, engagements, scope, etc.)
│   │   ├── auth/         # JWT generation, Password hashing, dependencies
│   │   ├── core/         # Config, Database setup, Audit log helper
│   │   ├── models/       # SQLAlchemy models (User, Org, AuditLog, Base)
│   │   └── schemas/      # Pydantic validation schemas
│   ├── tests/            # Test suite (fixtures, unit, integration tests)
│   ├── alembic/          # Database migrations configuration & versions
│   ├── Dockerfile        # Backend image configuration
│   └── requirements.txt  # Python package requirements
├── frontend/             # Frontend source folder (Phase 2+)
├── docker-compose.yml    # Development environment setup
└── README.md             # Project documentation
```

---

## Development Setup

### 1. Local Python Setup (Virtual Environment)
Navigate to the `backend/` directory:
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

### 2. Run Database Migrations
Initialize local SQLite migrations or Postgres:
```bash
# Setup database schema with Alembic
$env:DATABASE_URL="sqlite:///./test.db"  # Windows PowerShell
alembic upgrade head
```

### 3. Run Automated Tests
Execute the tests locally:
```bash
$env:PYTHONPATH="."
pytest tests/
```

### 4. Running the Development Server (Docker Compose)
Start all microservices (Postgres, Redis, and FastAPI Backend):
```bash
docker compose up --build
```
The FastAPI documentation will be available at `http://localhost:8000/docs`.

---

## Safety Controls & Security Boundaries
- **Tenant Isolation**: Handled via row-level FastAPI dependencies checking user organization scopes.
- **Append-Only Auditing**: Every high-impact action (login, registration, scan start, findings adjustment) is written to an immutable audit database table.
- **Strict Scope Boundaries**: Scanners enforce hostname/IP restrictions via DNS pinning and redirect re-evaluation to prevent Server-Side Request Forgery (SSRF) and target bypass (Phase 2 Scope Engine).
