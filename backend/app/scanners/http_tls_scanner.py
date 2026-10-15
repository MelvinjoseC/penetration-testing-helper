import socket
import ssl
import datetime
from typing import Any, Dict, List
import httpx
from app.scanners.base import ScannerPlugin, NormalizedFinding

class HttpTlsScannerPlugin(ScannerPlugin):
    name = "http_tls_scanner"
    version = "1.0.0"
    risk_level = "safe"

    async def execute(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs HTTP and TLS inspections against the target.
        """
        results = []
        
        # 1. Normalize target URL
        if not target.startswith("http://") and not target.startswith("https://"):
            target_url = f"https://{target}"
        else:
            target_url = target
            
        # Parse host
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        scheme = parsed.scheme
        port = parsed.port or (443 if scheme == "https" else 80)
        
        # 2. Perform HTTP verification
        try:
            # We enforce a strict timeout of 5 seconds to ensure safety
            # In testing, we disable SSL verification to check for header presence
            async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
                response = await client.get(target_url)
                
                # Save raw transaction evidence
                http_evidence = {
                    "url": target_url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "cookies": [{"name": k, "value": v} for k, v in client.cookies.items()] if hasattr(client, "cookies") else [],
                    "response_snippet": response.text[:2000],
                    "request_headers": dict(response.request.headers),
                    "request_method": response.request.method
                }
                results.append({
                    "check_type": "http_inspection",
                    "status": "success",
                    "evidence": http_evidence
                })
        except Exception as e:
            results.append({
                "check_type": "http_inspection",
                "status": "failed",
                "error": str(e)
            })

        # 3. Perform TLS Certificate inspection (only for HTTPS targets)
        if scheme == "https":
            try:
                context = ssl.create_default_context()
                # Bypass standard hostname match validation to retrieve raw cert attributes
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Query TLS details
                with socket.create_connection((host, port), timeout=5.0) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        from cryptography import x509
                        import datetime as dt
                        cert_obj = x509.load_der_x509_certificate(der_cert)
                        
                        not_before = cert_obj.not_valid_before_utc
                        not_after = cert_obj.not_valid_after_utc
                        
                        subject_str = cert_obj.subject.rfc4514_string()
                        issuer_str = cert_obj.issuer.rfc4514_string()
                        
                        subject_dict = {"CN": subject_str}
                        issuer_dict = {"CN": issuer_str}
                        
                        results.append({
                            "check_type": "tls_inspection",
                            "status": "success",
                            "evidence": {
                                "subject": subject_dict,
                                "issuer": issuer_dict,
                                "not_before": not_before.isoformat(),
                                "not_after": not_after.isoformat(),
                                "expired": dt.datetime.now(dt.timezone.utc) > not_after,
                                "cipher": ssock.cipher()
                            }
                        })
            except Exception as e:
                results.append({
                    "check_type": "tls_inspection",
                    "status": "failed",
                    "error": str(e)
                })
                
        return results

    def parse_results(self, raw_results: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        findings = []
        
        http_data = next((r for r in raw_results if r["check_type"] == "http_inspection"), None)
        tls_data = next((r for r in raw_results if r["check_type"] == "tls_inspection"), None)
        
        # 1. Evaluate HTTP headers and banners
        if http_data and http_data["status"] == "success":
            evidence = http_data["evidence"]
            headers = {k.lower(): v for k, v in evidence["headers"].items()}
            url = evidence["url"]
            
            # Check for Verbose Server Header
            server_header = headers.get("server")
            if server_header:
                findings.append(NormalizedFinding(
                    title="Verbose Server Header Banner Disclosure",
                    severity="Info",
                    confidence="Confirmed",
                    url=url,
                    description=f"The server returned a Server header containing version information: '{server_header}'.",
                    technical_details=f"Banner leakage helps attackers fingerprint the infrastructure and search for known public CVE vulnerabilities.",
                    evidence=evidence,
                    request=f"GET {url}",
                    response=f"HTTP/1.1 {evidence['status_code']}\nServer: {server_header}",
                    cwe="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cvss=0.0,
                    remediation="Disable or sanitize the Server banner header output in your web server configurations."
                ))
                
            # Check for X-Powered-By Header
            powered_by = headers.get("x-powered-by")
            if powered_by:
                findings.append(NormalizedFinding(
                    title="Information Disclosure: X-Powered-By Header Present",
                    severity="Info",
                    confidence="Confirmed",
                    url=url,
                    description=f"The server returned the X-Powered-By header: '{powered_by}'.",
                    technical_details=f"This discloses the runtime execution stack technologies.",
                    evidence=evidence,
                    request=f"GET {url}",
                    response=f"HTTP/1.1 {evidence['status_code']}\nX-Powered-By: {powered_by}",
                    cwe="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cvss=0.0,
                    remediation="Configure your web application server to omit the X-Powered-By HTTP response header."
                ))

            # Security Headers analysis
            missing_headers = []
            
            if "content-security-policy" not in headers:
                missing_headers.append(("Content-Security-Policy", "Medium", "CWE-1021", "A05:2021-Security Misconfiguration", 4.3, "Define a Content-Security-Policy header to control browser execution boundaries."))
            if "x-frame-options" not in headers:
                missing_headers.append(("X-Frame-Options", "Low", "CWE-1027", "A05:2021-Security Misconfiguration", 3.1, "Add the X-Frame-Options header (DENY or SAMEORIGIN) to mitigate Clickjacking attacks."))
            if "x-content-type-options" not in headers:
                missing_headers.append(("X-Content-Type-Options", "Low", "CWE-116", "A05:2021-Security Misconfiguration", 3.1, "Add the X-Content-Type-Options: nosniff header to prevent MIME-sniffing."))
            if "referrer-policy" not in headers:
                missing_headers.append(("Referrer-Policy", "Low", "CWE-116", "A05:2021-Security Misconfiguration", 3.1, "Add Referrer-Policy header (e.g. strict-origin-when-cross-origin) to prevent leakage of sensitive URL paths/tokens."))
            if "permissions-policy" not in headers and "feature-policy" not in headers:
                missing_headers.append(("Permissions-Policy", "Low", "CWE-16", "A05:2021-Security Misconfiguration", 2.5, "Configure Permissions-Policy header to restrict browser APIs like camera, microphone, and geolocation."))
            if url.startswith("https://") and "strict-transport-security" not in headers:
                missing_headers.append(("Strict-Transport-Security", "Medium", "CWE-319", "A02:2021-Cryptographic Failures", 5.3, "Implement Strict-Transport-Security header (max-age=31536000; includeSubDomains; preload) to prevent SSL stripping."))
                
            for h_name, severity, cwe, owasp, cvss, rem in missing_headers:
                findings.append(NormalizedFinding(
                    title=f"Missing Security Header: {h_name}",
                    severity=severity,
                    confidence="Confirmed",
                    url=url,
                    description=f"The website lacks the {h_name} response header, increasing exposure to client-side attacks.",
                    technical_details=f"Without {h_name}, modern web browsers fail to enforce strict client-side sandbox rules.",
                    evidence=evidence,
                    request=f"GET {url}",
                    response=None,
                    cwe=cwe,
                    owasp_category=owasp,
                    cvss=cvss,
                    remediation=rem
                ))

            # CORS Misconfiguration Analysis
            cors_origin = headers.get("access-control-allow-origin")
            cors_creds = headers.get("access-control-allow-credentials", "").lower() == "true"
            if cors_origin == "*" and cors_creds:
                findings.append(NormalizedFinding(
                    title="Critical CORS Configuration: Wildcard Origin with Credentials",
                    severity="High",
                    confidence="Confirmed",
                    url=url,
                    description="The server returns 'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true'.",
                    technical_details="Browsers generally reject this combination, but misconfigured proxies or custom user agents can leak sensitive session-authenticated data across origins.",
                    evidence=evidence,
                    request=f"GET {url}",
                    response=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    cwe="CWE-942",
                    owasp_category="A01:2021-Broken Access Control",
                    cvss=7.5,
                    remediation="Explicitly specify trusted origins in Access-Control-Allow-Origin instead of wildcard when credentials are supported."
                ))
            elif cors_origin == "*":
                findings.append(NormalizedFinding(
                    title="Permissive CORS Policy: Wildcard Access-Control-Allow-Origin",
                    severity="Info",
                    confidence="Confirmed",
                    url=url,
                    description="The server returns 'Access-Control-Allow-Origin: *', allowing any arbitrary third-party site to read response data.",
                    technical_details="Ensure that this endpoint does not expose confidential tenant or user data.",
                    evidence=evidence,
                    request=f"GET {url}",
                    response=f"Access-Control-Allow-Origin: *",
                    cwe="CWE-942",
                    owasp_category="A01:2021-Broken Access Control",
                    cvss=3.7,
                    remediation="Restrict Access-Control-Allow-Origin to specific authorized origins if endpoint content is private or sensitive."
                ))
                
            # Cookie Security Analysis
            # Check Set-Cookie headers in the response
            set_cookie_headers = [v for k, v in evidence["headers"].items() if k.lower() == "set-cookie"]
            for cookie_header in set_cookie_headers:
                cookie_lower = cookie_header.lower()
                cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "Cookie"
                
                issues = []
                if "httponly" not in cookie_lower:
                    issues.append("HttpOnly flag is missing (exposing the cookie to XSS read access)")
                if "secure" not in cookie_lower:
                    issues.append("Secure flag is missing (transmitting the cookie over plaintext channel)")
                if "samesite" not in cookie_lower:
                    issues.append("SameSite attribute is missing (increasing CSRF vulnerability risk)")
                    
                if issues:
                    findings.append(NormalizedFinding(
                        title=f"Insecure Cookie Configuration: {cookie_name}",
                        severity="Low",
                        confidence="Confirmed",
                        url=url,
                        description=f"The cookie '{cookie_name}' is set with insecure attributes: " + " and ".join(issues) + ".",
                        technical_details=f"Raw header value: '{cookie_header}'",
                        evidence=evidence,
                        request=f"GET {url}",
                        response=f"Set-Cookie: {cookie_header}",
                        cwe="CWE-614",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cvss=3.5,
                        remediation=f"Ensure that all sensitive session cookies are configured with 'HttpOnly', 'Secure', and 'SameSite=Lax/Strict' attributes in production."
                    ))

        # 2. Evaluate TLS details
        if tls_data and tls_data["status"] == "success":
            evidence = tls_data["evidence"]
            if evidence.get("expired"):
                findings.append(NormalizedFinding(
                    title="Expired SSL/TLS Certificate",
                    severity="High",
                    confidence="Confirmed",
                    url=None,
                    description=f"The target's TLS/SSL certificate is expired.",
                    technical_details=f"Certificate expired on: {evidence['not_after']}",
                    evidence=evidence,
                    cwe="CWE-298",
                    owasp_category="A02:2021-Cryptographic Failures",
                    cvss=7.4,
                    remediation="Renew the SSL/TLS certificate with a valid certificate authority immediately."
                ))

            cipher_info = evidence.get("cipher")
            if cipher_info and isinstance(cipher_info, (tuple, list)) and len(cipher_info) > 1:
                cipher_name, proto_ver, bits = cipher_info[0], cipher_info[1], cipher_info[2]
                if proto_ver in ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"]:
                    findings.append(NormalizedFinding(
                        title=f"Deprecated TLS Protocol Version: {proto_ver}",
                        severity="Medium",
                        confidence="Confirmed",
                        url=None,
                        description=f"The server negotiates connection using deprecated protocol version '{proto_ver}'.",
                        technical_details=f"Cipher: {cipher_name}, Bits: {bits}. Deprecated protocols are vulnerable to downgrade attacks.",
                        evidence=evidence,
                        cwe="CWE-326",
                        owasp_category="A02:2021-Cryptographic Failures",
                        cvss=5.9,
                        remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 in server TLS configuration. Enforce TLS 1.2 or TLS 1.3 only."
                    ))
                
        return findings
