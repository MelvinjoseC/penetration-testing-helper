from typing import Any, Dict, List
from urllib.parse import urlparse
import dns.resolver
from app.scanners.base import ScannerPlugin, NormalizedFinding

class PassiveDnsScannerPlugin(ScannerPlugin):
    name = "passive_dns_scanner"
    version = "1.0.0"
    risk_level = "passive"

    async def execute(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Executes passive DNS reconnaissance without sending active HTTP probes.
        Queries A, MX, TXT (SPF), and DMARC records.
        """
        results = []
        host = target.strip()
        if "://" in host:
            parsed = urlparse(host)
            host = parsed.hostname or host
        elif ":" in host:
            host = host.split(":")[0]

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        # 1. Query A / IPv4 records
        try:
            a_answers = resolver.resolve(host, "A")
            a_records = [r.to_text() for r in a_answers]
            results.append({
                "check_type": "dns_a",
                "status": "success",
                "host": host,
                "records": a_records
            })
        except Exception as e:
            results.append({
                "check_type": "dns_a",
                "status": "failed",
                "host": host,
                "error": str(e)
            })

        # 2. Query MX records
        try:
            mx_answers = resolver.resolve(host, "MX")
            mx_records = [f"{r.preference} {r.exchange.to_text()}" for r in mx_answers]
            results.append({
                "check_type": "dns_mx",
                "status": "success",
                "host": host,
                "records": mx_records
            })
        except Exception as e:
            results.append({
                "check_type": "dns_mx",
                "status": "not_found",
                "host": host,
                "error": str(e)
            })

        # 3. Query TXT / SPF records
        try:
            txt_answers = resolver.resolve(host, "TXT")
            txt_records = []
            for r in txt_answers:
                for s in r.strings:
                    txt_records.append(s.decode("utf-8", errors="replace"))

            spf_records = [t for t in txt_records if t.startswith("v=spf1")]
            results.append({
                "check_type": "dns_spf",
                "status": "success",
                "host": host,
                "spf_records": spf_records,
                "all_txt_records": txt_records
            })
        except Exception as e:
            results.append({
                "check_type": "dns_spf",
                "status": "failed",
                "host": host,
                "spf_records": [],
                "error": str(e)
            })

        # 4. Query DMARC record (_dmarc.<host>)
        dmarc_host = f"_dmarc.{host}"
        try:
            dmarc_answers = resolver.resolve(dmarc_host, "TXT")
            dmarc_records = []
            for r in dmarc_answers:
                for s in r.strings:
                    dmarc_records.append(s.decode("utf-8", errors="replace"))
            results.append({
                "check_type": "dns_dmarc",
                "status": "success",
                "host": dmarc_host,
                "records": dmarc_records
            })
        except Exception as e:
            results.append({
                "check_type": "dns_dmarc",
                "status": "not_found",
                "host": dmarc_host,
                "records": [],
                "error": str(e)
            })

        return results

    def parse_results(self, raw_results: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        findings = []

        spf_data = next((r for r in raw_results if r["check_type"] == "dns_spf"), None)
        dmarc_data = next((r for r in raw_results if r["check_type"] == "dns_dmarc"), None)

        # 1. Evaluate SPF Policy
        if spf_data:
            host = spf_data.get("host", "")
            spf_records = spf_data.get("spf_records", [])
            if not spf_records:
                findings.append(NormalizedFinding(
                    title="Missing Sender Policy Framework (SPF) Record",
                    severity="Medium",
                    confidence="Confirmed",
                    url=None,
                    endpoint=host,
                    description=f"The domain '{host}' does not publish an SPF (Sender Policy Framework) TXT record.",
                    technical_details="Absence of SPF enables unauthorized threat actors to spoof outbound emails claiming to originate from this domain.",
                    evidence=spf_data,
                    cwe="CWE-358",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cvss=5.3,
                    remediation="Publish a valid SPF record (e.g., 'v=spf1 include:_spf.example.com -all') in DNS TXT records."
                ))
            else:
                for rec in spf_records:
                    if "+all" in rec:
                        findings.append(NormalizedFinding(
                            title="Overly Permissive SPF Record (+all Allowed)",
                            severity="High",
                            confidence="Confirmed",
                            url=None,
                            endpoint=host,
                            description=f"The SPF record '{rec}' contains '+all', explicitly authorizing any mail server in the world to spoof this domain.",
                            technical_details=f"Record: '{rec}'",
                            evidence=spf_data,
                            cwe="CWE-358",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cvss=7.5,
                            remediation="Replace '+all' with '-all' (hard fail) or '~all' (soft fail) in the SPF TXT record."
                        ))

        # 2. Evaluate DMARC Policy
        if dmarc_data:
            host = dmarc_data.get("host", "")
            dmarc_records = [r for r in dmarc_data.get("records", []) if r.startswith("v=DMARC1")]
            if not dmarc_records:
                findings.append(NormalizedFinding(
                    title="Missing DMARC Email Protection Policy",
                    severity="Medium",
                    confidence="Confirmed",
                    url=None,
                    endpoint=host,
                    description=f"No DMARC policy record was found at '{host}'.",
                    technical_details="Without DMARC, receiving email servers cannot verify whether domain emails align with SPF and DKIM signatures.",
                    evidence=dmarc_data,
                    cwe="CWE-358",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cvss=5.3,
                    remediation="Create a DMARC TXT record at '_dmarc.<domain>' with a policy (e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com')."
                ))
            else:
                for rec in dmarc_records:
                    if "p=none" in rec.lower():
                        findings.append(NormalizedFinding(
                            title="Weak DMARC Policy (p=none)",
                            severity="Low",
                            confidence="Confirmed",
                            url=None,
                            endpoint=host,
                            description=f"The DMARC policy at '{host}' is configured with 'p=none', which operates in monitoring-only mode.",
                            technical_details=f"Current record: '{rec}'. Spoofed emails will not be quarantined or rejected.",
                            evidence=dmarc_data,
                            cwe="CWE-358",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cvss=3.5,
                            remediation="Upgrade the DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' after initial monitoring."
                        ))

        return findings
