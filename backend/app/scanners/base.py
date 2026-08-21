from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class NormalizedFinding(BaseModel):
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    confidence: str  # Confirmed, Likely, Potential
    url: Optional[str] = None
    endpoint: Optional[str] = None
    description: str
    technical_details: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None  # Dict of request/response/headers
    request: Optional[str] = None
    response: Optional[str] = None
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss: Optional[float] = None
    remediation: Optional[str] = None


class ScannerPlugin:
    name: str = "base_scanner"
    version: str = "1.0.0"
    risk_level: str = "safe"  # passive, safe, intrusive

    async def execute(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Executes the raw scanning actions. Returns raw results.
        Must be overridden by subclasses.
        """
        raise NotImplementedError

    def parse_results(self, raw_results: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        """
        Translates raw scanner JSON outputs into NormalizedFinding instances.
        Must be overridden by subclasses.
        """
        raise NotImplementedError
