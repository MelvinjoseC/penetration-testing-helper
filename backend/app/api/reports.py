import uuid
import datetime
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.deps import get_current_user
from app.models.user import User
from app.models.engagement import Engagement
from app.models.scan import Finding

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.post("", response_class=Response)
def generate_report(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    engagement_id: uuid.UUID
) -> Any:
    """
    Generate an HTML penetration-testing report containing Executive and Technical summaries.
    """
    # 1. Verify engagement owner
    engagement = db.query(Engagement).filter(
        Engagement.id == engagement_id,
        Engagement.organization_id == current_user.organization_id
    ).first()
    
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found."
        )

    # 2. Gather findings
    findings = db.query(Finding).filter(Finding.engagement_id == engagement_id).all()
    
    # Group findings by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))
    
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1

    # 3. Construct HTML
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Penetration Testing Assessment Report - {engagement.name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
        }}
        h1, h2, h3, h4 {{
            color: #1a202c;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 8px;
        }}
        .header-table, .findings-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .header-table td, .header-table th, .findings-table td, .findings-table th {{
            border: 1px solid #cbd5e0;
            padding: 12px;
            text-align: left;
        }}
        .header-table th, .findings-table th {{
            background-color: #f7fafc;
            font-weight: 600;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            display: inline-block;
        }}
        .badge-Critical {{ background-color: #fed7d7; color: #9b2c2c; }}
        .badge-High {{ background-color: #feebc8; color: #9c4221; }}
        .badge-Medium {{ background-color: #e2e8f0; color: #4a5568; }}
        .badge-Low {{ background-color: #ebf8ff; color: #2b6cb0; }}
        .badge-Info {{ background-color: #ebfaf0; color: #234e52; }}
        .section {{
            margin-bottom: 40px;
        }}
        .finding-card {{
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
            background-color: #fff;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .finding-title {{
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        pre {{
            background-color: #f7fafc;
            padding: 12px;
            border-radius: 4px;
            overflow-x: auto;
            border: 1px solid #e2e8f0;
            font-size: 13px;
        }}
        .footer {{
            text-align: center;
            font-size: 12px;
            color: #718096;
            margin-top: 60px;
            border-top: 1px solid #e2e8f0;
            padding-top: 20px;
        }}
    </style>
</head>
<body>

    <div class="section" style="text-align: center; margin-bottom: 60px;">
        <h1 style="border: none; font-size: 32px;">Penetration Testing Assessment Report</h1>
        <p style="font-size: 18px; color: #4a5568;">Engagement: {engagement.name}</p>
        <p style="font-size: 14px; color: #718096;">Generated for: {engagement.company}</p>
        <p style="font-size: 14px; color: #718096;">Authorization Reference: {engagement.authorization_reference}</p>
    </div>

    <div class="section">
        <h2>1. Executive Summary</h2>
        <p>
            An authorized security assessment was conducted against the target assets defined within the engagement scope for <strong>{engagement.company}</strong>.
            The primary goal of this assessment was to identify potential security exposures, configurations anomalies, and compliance risks using safe, non-destructive methodologies.
        </p>
        
        <h3>Vulnerability Summary Breakdown</h3>
        <table class="header-table">
            <thead>
                <tr>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th>Informational</th>
                    <th>Total Findings</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><span class="badge badge-Critical">{severity_counts["Critical"]}</span></td>
                    <td><span class="badge badge-High">{severity_counts["High"]}</span></td>
                    <td><span class="badge badge-Medium">{severity_counts["Medium"]}</span></td>
                    <td><span class="badge badge-Low">{severity_counts["Low"]}</span></td>
                    <td><span class="badge badge-Info">{severity_counts["Info"]}</span></td>
                    <td><strong>{len(findings)}</strong></td>
                </tr>
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>2. Scope & Target Boundaries</h2>
        <p>The following targets were explicitly defined inside the authorized testing boundary:</p>
        <table class="header-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Scope Pattern</th>
                    <th>Classification</th>
                </tr>
            </thead>
            <tbody>
    """
    for scope in engagement.scopes:
        classification = "Excluded" if scope.is_excluded else "Allowed"
        html_content += f"""
                <tr>
                    <td>{scope.type.capitalize()}</td>
                    <td><code>{scope.pattern}</code></td>
                    <td><strong>{classification}</strong></td>
                </tr>
        """
        
    html_content += """
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>3. Detailed Technical Findings</h2>
    """
    
    if not sorted_findings:
        html_content += "<p>No vulnerabilities or security findings were identified during the safe assessment execution.</p>"
    else:
        for idx, finding in enumerate(sorted_findings, 1):
            html_content += f"""
            <div class="finding-card">
                <div class="finding-title">
                    {idx}. {finding.title} 
                    <span class="badge badge-{finding.severity}">{finding.severity}</span>
                </div>
                <p><strong>CWE:</strong> {finding.cwe or "N/A"} | <strong>OWASP Category:</strong> {finding.owasp_category or "N/A"}</p>
                <p><strong>Description:</strong> {finding.description}</p>
            """
            
            if finding.technical_details:
                html_content += f"<p><strong>Technical Details:</strong> {finding.technical_details}</p>"
            if finding.remediation:
                html_content += f"<p><strong>Remediation Guidance:</strong> {finding.remediation}</p>"
                
            if finding.request:
                html_content += f"<h4>Raw Request Evidence:</h4><pre>{finding.request}</pre>"
            if finding.response:
                html_content += f"<h4>Raw Response Evidence:</h4><pre>{finding.response}</pre>"
                
            html_content += "</div>"

    html_content += f"""
    </div>

    <div class="footer">
        <p>CONFIDENTIAL ASSESSMENT REPORT - FOR INTERNAL USE ONLY</p>
        <p>Platform Orchestrator &bull; Generated at {datetime.datetime.utcnow().isoformat() if hasattr(datetime, "datetime") else ""}</p>
    </div>

</body>
</html>
"""
    return Response(content=html_content, media_type="text/html")
