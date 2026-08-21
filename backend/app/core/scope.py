import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Optional, Tuple
from app.models.engagement import Scope

def resolve_hostname(host: str) -> List[str]:
    """
    Resolves a hostname to a list of IP addresses (IPv4 and IPv6).
    """
    try:
        # Use socket.getaddrinfo to resolve both IPv4 and IPv6 addresses
        addr_info = socket.getaddrinfo(host, None)
        ips = list(set(info[4][0] for info in addr_info))
        return ips
    except socket.gaierror:
        return []

def match_domain(pattern: str, domain: str) -> bool:
    """
    Matches domain patterns supporting exact matches and wildcard subdomains.
    Example:
      pattern: *.mycompany.com
      domain: staging.mycompany.com -> True
      domain: evil.com.mycompany.com -> True
      domain: mycompany.com.evil.com -> False
    """
    pattern = pattern.lower().strip()
    domain = domain.lower().strip()
    if pattern == domain:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain == suffix or domain.endswith("." + suffix)
    return False

def match_ip_or_cidr(pattern: str, ip_str: str) -> bool:
    """
    Checks if an IP address matches a pattern (which could be an exact IP or CIDR network).
    """
    try:
        target_ip = ipaddress.ip_address(ip_str)
        if "/" in pattern:
            # CIDR notation
            network = ipaddress.ip_network(pattern, strict=False)
            return target_ip in network
        else:
            # Single IP
            pattern_ip = ipaddress.ip_address(pattern)
            return target_ip == pattern_ip
    except ValueError:
        return False

def parse_target(target: str) -> Tuple[str, Optional[int], Optional[str]]:
    """
    Parses a target string (which could be a URL, IP, hostname, or CIDR)
    into a host/ip, optional port, and optional path prefix.
    """
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port
        path = parsed.path
        return host, port, path
    
    # Try parsing host:port
    if ":" in target and not target.endswith("]"):  # Handle IPv6 brackets vs ports
        # Check if it could be an IPv6 address without brackets
        parts = target.split(":")
        if len(parts) == 2:
            return parts[0], int(parts[1]), None
            
    return target, None, None

def matches_rule(
    rule_type: str, 
    rule_pattern: str, 
    target_host: str, 
    target_port: Optional[int], 
    target_path: Optional[str], 
    resolved_ips: List[str]
) -> bool:
    """
    Determines if a target matches a specific scope rule based on rule type and pattern.
    """
    rule_pattern = rule_pattern.lower().strip()
    
    # 1. URL pattern rule
    if "://" in rule_pattern:
        rule_parsed = urlparse(rule_pattern)
        rule_host = rule_parsed.hostname or ""
        rule_port = rule_parsed.port
        rule_path = rule_parsed.path.rstrip("/")
        
        # Match host
        if not match_domain(rule_host, target_host) and not any(match_ip_or_cidr(rule_host, ip) for ip in resolved_ips):
            return False
            
        # Match port
        if rule_port is not None and target_port is not None and rule_port != target_port:
            return False
            
        # Match path prefix
        target_path_str = target_path or "/"
        if not target_path_str.startswith("/"):
            target_path_str = "/" + target_path_str
        target_path_str = target_path_str.rstrip("/")
        
        rule_path_str = rule_path.rstrip("/")
        if rule_path_str:
            if not target_path_str.startswith(rule_path_str):
                return False
        return True

    # 2. IP / CIDR rule
    try:
        # Check if the pattern is a valid network/IP
        if "/" in rule_pattern or ipaddress.ip_address(rule_pattern):
            # Check target host if it is a raw IP
            try:
                ipaddress.ip_address(target_host)
                if match_ip_or_cidr(rule_pattern, target_host):
                    return True
            except ValueError:
                pass
            # Check resolved IPs of the target host
            return any(match_ip_or_cidr(rule_pattern, ip) for ip in resolved_ips)
    except ValueError:
        pass

    # 3. Domain rule
    return match_domain(rule_pattern, target_host)

class ScopeService:
    @staticmethod
    def is_allowed(target: str, scope_rules: List[Scope]) -> bool:
        """
        Enforces target scope check.
        - Normalize and parse target.
        - Resolve target hostname to prevent DNS rebinding SSRF.
        - Evaluate target host + resolved IPs against EXCLUDED rules first.
        - Evaluate target host + resolved IPs against INCLUDED rules.
        - Returns True if allowed, False otherwise.
        """
        host, port, path = parse_target(target)
        if not host:
            return False
            
        # Resolve IPs of the target if host is not already an IP address
        is_raw_ip = False
        try:
            ipaddress.ip_address(host)
            is_raw_ip = True
        except ValueError:
            pass

        resolved_ips = [host] if is_raw_ip else resolve_hostname(host)
        
        # Step 1: Check Exclusions (Explicitly out-of-scope)
        for rule in scope_rules:
            if rule.is_excluded:
                if matches_rule(rule.type, rule.pattern, host, port, path, resolved_ips):
                    return False
                    
        # Step 2: Check Inclusions (In-scope)
        for rule in scope_rules:
            if not rule.is_excluded:
                if matches_rule(rule.type, rule.pattern, host, port, path, resolved_ips):
                    return True
                    
        return False
