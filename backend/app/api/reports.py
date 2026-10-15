import uuid
import datetime
import html
import json
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Response, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.deps import get_current_user
from app.models.user import User
from app.models.engagement import Engagement
from app.models.scan import Finding

def esc(val: Any) -> str:
    return html.escape(str(val)) if val is not None else ""

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.post("", response_class=Response)
def generate_report(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    engagement_id: uuid.UUID,
    format: str = Query("html", description="Output format: html, json, or markdown")
) -> Any:
    """
    Generate a penetration-testing assessment report in HTML, JSON, or Markdown format.
    """
    format_clean = format.lower().strip()
    if format_clean not in {"html", "json", "markdown"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{format}'. Supported formats are: html, json, markdown."
        )

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

    generated_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 3. Format: JSON Export
    if format_clean == "json":
        report_data = {
            "report_title": f"Penetration Testing Assessment Report - {engagement.name}",
            "generated_at": generated_timestamp,
            "engagement": {
                "id": str(engagement.id),
                "name": engagement.name,
                "company": engagement.company,
                "authorization_reference": engagement.authorization_reference,
                "status": engagement.status,
                "is_verified": engagement.is_verified,
                "start_date": engagement.start_date.isoformat() if engagement.start_date else None,
                "end_date": engagement.end_date.isoformat() if engagement.end_date else None,
            },
            "summary": {
                "total_findings": len(findings),
                "severity_breakdown": severity_counts,
            },
            "scopes": [
                {
                    "id": str(s.id),
                    "type": s.type,
                    "pattern": s.pattern,
                    "is_excluded": s.is_excluded
                }
                for s in engagement.scopes
            ],
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "status": f.status,
                    "cwe": f.cwe,
                    "owasp_category": f.owasp_category,
                    "cvss": f.cvss,
                    "url": f.url,
                    "description": f.description,
                    "technical_details": f.technical_details,
                    "remediation": f.remediation,
                    "scanner": f.scanner,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in sorted_findings
            ]
        }
        return Response(
            content=json.dumps(report_data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="report-{engagement.id}.json"'}
        )

    # 4. Format: Markdown Export
    if format_clean == "markdown":
        md_lines = [
            f"# Penetration Testing Assessment Report: {engagement.name}",
            f"**Target Company:** {engagement.company}  ",
            f"**Authorization Reference:** {engagement.authorization_reference}  ",
            f"**Report Generated:** {generated_timestamp}  ",
            "",
            "## 1. Executive Summary",
            "",
            f"An authorized penetration-testing assessment was performed against configured assets for **{engagement.company}**.",
            "",
            "| Severity | Count |",
            "| :--- | :--- |",
            f"| Critical | {severity_counts['Critical']} |",
            f"| High | {severity_counts['High']} |",
            f"| Medium | {severity_counts['Medium']} |",
            f"| Low | {severity_counts['Low']} |",
            f"| Informational | {severity_counts['Info']} |",
            f"| **Total** | **{len(findings)}** |",
            "",
            "## 2. Assessment Scope",
            "",
            "| Type | Pattern | Status |",
            "| :--- | :--- | :--- |",
        ]
        for s in engagement.scopes:
            status_text = "Excluded" if s.is_excluded else "Allowed"
            md_lines.append(f"| {s.type} | `{s.pattern}` | {status_text} |")

        md_lines.extend(["", "## 3. Detailed Technical Findings", ""])
        if not sorted_findings:
            md_lines.append("No security exposures identified.")
        else:
            for idx, f in enumerate(sorted_findings, 1):
                md_lines.extend([
                    f"### {idx}. {f.title} ({f.severity})",
                    f"- **Status:** {f.status}",
                    f"- **CWE:** {f.cwe or 'N/A'}",
                    f"- **OWASP Category:** {f.owasp_category or 'N/A'}",
                    f"- **CVSS:** {f.cvss if f.cvss is not None else 'N/A'}",
                    f"- **Endpoint/URL:** {f.url or f.endpoint or 'N/A'}",
                    "",
                    f"**Description:**  ",
                    f"{f.description}",
                    "",
                ])
                if f.technical_details:
                    md_lines.extend([
                        f"**Technical Details:**  ",
                        f"{f.technical_details}",
                        "",
                    ])
                if f.remediation:
                    md_lines.extend([
                        f"**Remediation Guidance:**  ",
                        f"{f.remediation}",
                        "",
                    ])
                if f.request:
                    md_lines.extend([
                        "**Request:**",
                        "```http",
                        f.request,
                        "```",
                        "",
                    ])
                if f.response:
                    md_lines.extend([
                        "**Response:**",
                        "```http",
                        f.response,
                        "```",
                        "",
                    ])

        md_content = "\n".join(md_lines)
        return Response(
            content=md_content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="report-{engagement.id}.md"'}
        )

    # 5. Format: HTML Export (Default)
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Penetration Testing Assessment Report - {esc(engagement.name)}</title>
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
        <p style="font-size: 18px; color: #4a5568;">Engagement: {esc(engagement.name)}</p>
        <p style="font-size: 14px; color: #718096;">Generated for: {esc(engagement.company)}</p>
        <p style="font-size: 14px; color: #718096;">Authorization Reference: {esc(engagement.authorization_reference)}</p>
    </div>

    <div class="section">
        <h2>1. Executive Summary</h2>
        <p>
            An authorized security assessment was conducted against the target assets defined within the engagement scope for <strong>{esc(engagement.company)}</strong>.
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
                    <td>{esc(scope.type.capitalize())}</td>
                    <td><code>{esc(scope.pattern)}</code></td>
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
                    {idx}. {esc(finding.title)} 
                    <span class="badge badge-{esc(finding.severity)}">{esc(finding.severity)}</span>
                </div>
                <p><strong>CWE:</strong> {esc(finding.cwe or "N/A")} | <strong>OWASP Category:</strong> {esc(finding.owasp_category or "N/A")}</p>
                <p><strong>Description:</strong> {esc(finding.description)}</p>
            """
            
            if finding.technical_details:
                html_content += f"<p><strong>Technical Details:</strong> {esc(finding.technical_details)}</p>"
            if finding.remediation:
                html_content += f"<p><strong>Remediation Guidance:</strong> {esc(finding.remediation)}</p>"
                
            if finding.request:
                html_content += f"<h4>Raw Request Evidence:</h4><pre>{esc(finding.request)}</pre>"
            if finding.response:
                html_content += f"<h4>Raw Response Evidence:</h4><pre>{esc(finding.response)}</pre>"
                
            html_content += "</div>"

    html_content += f"""
    </div>

    <div class="footer">
        <p>CONFIDENTIAL ASSESSMENT REPORT - FOR INTERNAL USE ONLY</p>
        <p>Platform Orchestrator &bull; Generated at {generated_timestamp}</p>
    </div>

</body>
</html>
"""
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="report-{engagement.id}.html"'}
    )
