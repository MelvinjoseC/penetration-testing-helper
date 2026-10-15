import asyncio
import hashlib
import uuid
import logging
import datetime
from sqlalchemy.orm import Session
from app.tasks.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.scan import Scan, Finding
from app.models.engagement import Engagement, Scope, Asset
from app.core.scope import ScopeService
from app.scanners.http_tls_scanner import HttpTlsScannerPlugin

logger = logging.getLogger(__name__)

def generate_finding_fingerprint(engagement_id: uuid.UUID, title: str, url: str, cwe: str) -> str:
    """
    Generates a unique SHA-256 fingerprint for deduplication.
    """
    raw = f"{engagement_id}:{title}:{url}:{cwe}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

@celery_app.task(name="app.tasks.scan_task.run_scan")
def run_scan(scan_id_str: str) -> str:
    """
    Executes an authorized security scan background task.
    """
    scan_id = uuid.UUID(scan_id_str)
    db: Session = SessionLocal()
    try:
        # 1. Fetch scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan with ID {scan_id_str} not found.")
            return "failed"
            
        # 2. Update status to running
        scan.status = "running"
        db.commit()
        db.refresh(scan)
        
        # 3. Retrieve engagement and scope rules
        engagement = db.query(Engagement).filter(Engagement.id == scan.engagement_id).first()
        if not engagement:
            scan.status = "failed"
            db.commit()
            return "failed"
            
        # 4. Scope Engine Enforcement Check
        scope_rules = db.query(Scope).filter(Scope.engagement_id == engagement.id).all()
        
        # Guard 1: Must be explicitly verified before scanning
        if not engagement.is_verified:
            scan.status = "failed"
            db.commit()
            
            # Record security violation finding
            violation = Finding(
                engagement_id=engagement.id,
                scan_id=scan.id,
                title="Security Scan Triggered on Unverified Target Domain",
                severity="High",
                confidence="Confirmed",
                description=f"A scan was requested for target '{scan.target}', but domain ownership/authorization has not been verified.",
                technical_details="Unauthorized scans are technically blocked to guarantee compliance rules.",
                scanner="core_orchestrator",
                fingerprint=generate_finding_fingerprint(engagement.id, "Unverified Domain Scan", scan.target, "CWE-862")
            )
            db.add(violation)
            db.commit()
            return "blocked"

        # Guard 2: Target must lie inside scope
        if not ScopeService.is_allowed(scan.target, scope_rules):
            scan.status = "failed"
            db.commit()
            
            # Record out of scope boundary violation
            violation = Finding(
                engagement_id=engagement.id,
                scan_id=scan.id,
                title="Security Scan Triggered Outside Configured Scope",
                severity="High",
                confidence="Confirmed",
                description=f"A scan was requested for target '{scan.target}', but this hostname or IP path is excluded or not explicitly allowed in the scope rules.",
                technical_details="Scans exceeding the allowed target boundaries are strictly blocked to prevent unauthorized testing.",
                scanner="core_orchestrator",
                fingerprint=generate_finding_fingerprint(engagement.id, "Out of Scope Scan Blocked", scan.target, "CWE-285")
            )
            db.add(violation)
            db.commit()
            return "blocked"

        # 5. Populate / Upsert target Asset
        asset = db.query(Asset).filter(
            Asset.engagement_id == engagement.id,
            Asset.value == scan.target
        ).first()
        
        if not asset:
            # Determine asset type
            asset_type = "web_app" if "://" in scan.target else "domain"
            asset = Asset(
                engagement_id=engagement.id,
                type=asset_type,
                value=scan.target,
                details={"discovered_during_scan": str(scan.id)}
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)

        # 6. Execute safe scanning plugins via Asyncio run block
        scanner = HttpTlsScannerPlugin()
        raw_results = asyncio.run(scanner.execute(scan.target, {}))
        
        # Update asset details with server findings metadata
        http_data = next((r for r in raw_results if r["check_type"] == "http_inspection"), None)
        if http_data and http_data["status"] == "success":
            asset.details = {
                **asset.details,
                "server_header": http_data["evidence"]["headers"].get("Server", "Unknown"),
                "status_code": http_data["evidence"]["status_code"],
                "last_seen": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            db.add(asset)
            db.commit()

        # 7. Normalize, deduplicate, and store findings
        normalized_findings = scanner.parse_results(raw_results)
        
        for norm in normalized_findings:
            fingerprint = generate_finding_fingerprint(
                engagement.id, 
                norm.title, 
                norm.url or "", 
                norm.cwe or ""
            )
            
            # Check for duplicates in this engagement
            existing_finding = db.query(Finding).filter(
                Finding.engagement_id == engagement.id,
                Finding.fingerprint == fingerprint
            ).first()
            
            if existing_finding:
                # Merge evidence
                evidence_list = existing_finding.evidence or {}
                if isinstance(evidence_list, dict):
                    evidence_list = [evidence_list]
                elif not isinstance(evidence_list, list):
                    evidence_list = []
                    
                evidence_list.append(norm.evidence)
                existing_finding.evidence = {"scans": evidence_list}
                existing_finding.request = norm.request or existing_finding.request
                existing_finding.response = norm.response or existing_finding.response
                db.add(existing_finding)
            else:
                # Create new Finding
                new_finding = Finding(
                    engagement_id=engagement.id,
                    scan_id=scan.id,
                    asset_id=asset.id,
                    title=norm.title,
                    severity=norm.severity,
                    confidence=norm.confidence,
                    url=norm.url,
                    endpoint=norm.endpoint,
                    description=norm.description,
                    technical_details=norm.technical_details,
                    evidence=norm.evidence,
                    request=norm.request,
                    response=norm.response,
                    cwe=norm.cwe,
                    owasp_category=norm.owasp_category,
                    cvss=norm.cvss,
                    remediation=norm.remediation,
                    scanner=scanner.name,
                    status="New",
                    fingerprint=fingerprint
                )
                db.add(new_finding)
                
        # 8. Mark scan completed
        scan.status = "completed"
        db.commit()
        return "completed"
        
    except Exception as e:
        logger.exception("Error executing scan task")
        if scan:
            scan.status = "failed"
            db.commit()
        return "failed"
    finally:
        db.close()
