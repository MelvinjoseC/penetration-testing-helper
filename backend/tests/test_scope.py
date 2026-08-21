import pytest
import socket
from unittest.mock import patch
from app.models.engagement import Scope
from app.core.scope import ScopeService

# Helper mock for hostname resolution
def mock_getaddrinfo(host, port, *args, **kwargs):
    if host == "staging.mycompany.com":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 80))]
    elif host == "payments.mycompany.com":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 80))]
    elif host == "localhost" or host == "127.0.0.1":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
    elif host == "evil.com":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))]
    raise socket.gaierror

@pytest.fixture(autouse=True)
def patch_dns():
    with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
        yield

def test_scope_in_and_out_rules():
    # Setup allowed and excluded scope rules
    scope_rules = [
        Scope(type="domain", pattern="*.mycompany.com", is_excluded=False),
        Scope(type="cidr", pattern="192.168.1.0/24", is_excluded=False),
        Scope(type="domain", pattern="payments.mycompany.com", is_excluded=True),
        Scope(type="cidr", pattern="127.0.0.0/8", is_excluded=True),
        Scope(type="url", pattern="https://staging.mycompany.com/api/v1/payments", is_excluded=True)
    ]

    # 1. Allowed domain
    assert ScopeService.is_allowed("staging.mycompany.com", scope_rules) is True

    # 2. Excluded subdomain
    assert ScopeService.is_allowed("payments.mycompany.com", scope_rules) is False

    # 3. Allowed IP within CIDR
    assert ScopeService.is_allowed("192.168.1.10", scope_rules) is True

    # 4. Out of scope IP
    assert ScopeService.is_allowed("10.0.0.1", scope_rules) is False

    # 5. Excluded local subnet IP
    assert ScopeService.is_allowed("127.0.0.1", scope_rules) is False

    # 6. Excluded URL path
    assert ScopeService.is_allowed("https://staging.mycompany.com/api/v1/payments", scope_rules) is False
    # Allowed URL path (different path)
    assert ScopeService.is_allowed("https://staging.mycompany.com/api/v1/users", scope_rules) is True

def test_scope_wildcard_matching():
    scope_rules = [
        Scope(type="domain", pattern="*.mycompany.com", is_excluded=False)
    ]
    # Suffix check verification
    assert ScopeService.is_allowed("test.mycompany.com", scope_rules) is True
    assert ScopeService.is_allowed("sub.test.mycompany.com", scope_rules) is True
    # Prevent suffix tricks (mycompany.com.evil.com should be denied)
    assert ScopeService.is_allowed("mycompany.com.evil.com", scope_rules) is False

def test_scope_dns_rebinding_bypass():
    scope_rules = [
        Scope(type="domain", pattern="*.mycompany.com", is_excluded=False),
        Scope(type="cidr", pattern="127.0.0.0/8", is_excluded=True) # Exclude local loopback
    ]
    
    # Target host claims to be in scope but resolves to excluded local IP
    # We patch DNS to make "evil-local.mycompany.com" resolve to "127.0.0.1"
    def dns_resolve_local(host, port, *args, **kwargs):
        if host == "evil-local.mycompany.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
        return mock_getaddrinfo(host, port, *args, **kwargs)

    with patch("socket.getaddrinfo", side_effect=dns_resolve_local):
        assert ScopeService.is_allowed("evil-local.mycompany.com", scope_rules) is False
