import httpx
import dns.resolver
import uuid

def generate_verification_token(engagement_id: uuid.UUID) -> str:
    """
    Generates a unique, deterministic token for verifying ownership of a domain.
    """
    return f"pentest-verification-{engagement_id}"

def verify_domain_dns(domain: str, token: str) -> bool:
    """
    Verifies domain ownership by querying TXT records at:
    _security-verification.<domain>
    """
    try:
        # Normalize target domain
        domain = domain.lower().strip()
        query_domain = f"_security-verification.{domain}"
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0
        
        answers = resolver.resolve(query_domain, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                # Decoded record must match verification token
                if txt_string.decode("utf-8").strip() == token.strip():
                    return True
    except Exception:
        pass
    return False

def verify_domain_http(domain: str, token: str) -> bool:
    """
    Verifies domain ownership by sending a safe HTTP request to:
    http://<domain>/.well-known/security-verification.txt
    """
    domain = domain.lower().strip()
    url = f"http://{domain}/.well-known/security-verification.txt"
    try:
        # Perform HTTP GET request with a strict 5 second timeout
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            response = client.get(url)
            if response.status_code == 200:
                content = response.text.strip()
                # Verify token presence
                return token.strip() in content
    except Exception:
        pass
    return False
