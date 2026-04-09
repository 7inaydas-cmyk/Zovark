"""Tests for EgressController domain allowlisting and proxy routing.

Important: The EgressController does NOT currently implement SSRF protection
for raw IP addresses (127.0.0.1, 169.254.169.254, 10.x, etc.) — only the
named NO_PROXY_HOSTS set and the ALLOWED_DOMAINS set are checked.
Tests reflect the *actual* implementation behaviour.

Covers:
  - validate_url: allowed domains, subdomains, internal bypass, blocked domains
  - get_proxy_config: internal → no proxy, external → proxy dict
  - is_internal: hostname membership and .internal suffix
  - EgressDeniedError raised for non-allowlisted hosts
  - Custom allowed_domains at construction time
"""
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER = os.path.abspath(os.path.join(_HERE, ".."))
if _WORKER not in sys.path:
    sys.path.insert(0, _WORKER)

from egress_controller import EgressController, EgressDeniedError
import pytest


# ---------------------------------------------------------------------------
# validate_url — allowed domains
# ---------------------------------------------------------------------------

class TestValidateURLAllowed:
    """Requests to allowlisted domains must return True."""

    def setup_method(self):
        self.ctrl = EgressController()

    @pytest.mark.parametrize("url", [
        "https://splunk.com/api/search",
        "https://api.crowdstrike.com/v2/detections",
        "https://sentinel.sentinelone.net/alerts",
        "https://virustotal.com/api/v3/files",
        "https://abuseipdb.com/check",
        "https://shodan.io/host/1.2.3.4",
        "https://slack.com/api/chat.postMessage",
        "https://pagerduty.com/incidents",
        "https://servicenow.com/api/now/table/incident",
        "https://elastic.co/guide",
    ])
    def test_allowlisted_domain(self, url):
        assert self.ctrl.validate_url(url) is True

    @pytest.mark.parametrize("url", [
        "https://api.crowdstrike.com/path",
        "https://eu1.splunk.com/search",
        "https://tenant.atlassian.net/browse/ISSUE-1",
        "https://sub.virustotal.com/report",
    ])
    def test_subdomain_of_allowlisted(self, url):
        assert self.ctrl.validate_url(url) is True


# ---------------------------------------------------------------------------
# validate_url — internal services bypass allowlist
# ---------------------------------------------------------------------------

class TestValidateURLInternal:
    """Internal service hostnames are always permitted."""

    def setup_method(self):
        self.ctrl = EgressController()

    @pytest.mark.parametrize("url", [
        "http://zovark-inference:8080/v1/chat/completions",
        "http://postgres:5432",
        "http://valkey:6379",
        "http://redis:6379",  # legacy alias kept in NO_PROXY allowlist
        "http://temporal:7233",
        "http://minio:9000",
        "http://nats:4222",
        "http://jaeger:14268",
        "http://zovark-api:8090/health",
        "http://pgbouncer:5432",
        "http://embedding-server:8001",
    ])
    def test_internal_service_allowed(self, url):
        assert self.ctrl.validate_url(url) is True

    def test_dot_internal_suffix_allowed(self):
        assert self.ctrl.validate_url("http://service.internal/path") is True

    def test_localhost_allowed_as_internal(self):
        # "localhost" is in NO_PROXY_HOSTS
        assert self.ctrl.validate_url("http://localhost:8080/test") is True


# ---------------------------------------------------------------------------
# validate_url — blocked domains
# ---------------------------------------------------------------------------

class TestValidateURLBlocked:
    """Non-allowlisted external domains must raise EgressDeniedError."""

    def setup_method(self):
        self.ctrl = EgressController()

    @pytest.mark.parametrize("url", [
        "https://evil.com/exfiltrate",
        "https://definitely-not-allowed.xyz/",
        "https://attacker.io/payload",
        "https://malware.download/dropper.exe",
        "https://google.com/search",        # popular but not in allowlist
        "https://github.com/user/repo",     # popular but not in allowlist
        "https://pastebin.com/raw/abc",
    ])
    def test_blocked_domain(self, url):
        with pytest.raises(EgressDeniedError):
            self.ctrl.validate_url(url)

    def test_error_message_contains_domain(self):
        try:
            self.ctrl.validate_url("https://notallowed.example/path")
        except EgressDeniedError as exc:
            assert "notallowed.example" in str(exc)
        else:
            pytest.fail("Expected EgressDeniedError was not raised")

    def test_subdomain_of_blocked_is_blocked(self):
        """sub.notallowed.xyz is blocked if notallowed.xyz is not in allowlist."""
        with pytest.raises(EgressDeniedError):
            self.ctrl.validate_url("https://sub.notallowed.xyz/path")

    def test_partial_domain_match_is_blocked(self):
        """splunk.com.evil.com must not match splunk.com."""
        with pytest.raises(EgressDeniedError):
            self.ctrl.validate_url("https://splunk.com.evil.com/api")


# ---------------------------------------------------------------------------
# Raw IP addresses — reflect actual implementation (no SSRF protection)
# ---------------------------------------------------------------------------

class TestValidateURLRawIP:
    """Raw IPs: the controller checks hostname against NO_PROXY_HOSTS and
    ALLOWED_DOMAINS only. Raw IPs are not in either set, so they are blocked
    (EgressDeniedError). This is the observed behaviour of the current impl.
    """

    def setup_method(self):
        self.ctrl = EgressController()

    def test_loopback_ip_blocked(self):
        """127.0.0.1 is not in NO_PROXY_HOSTS (only 'localhost' is)."""
        with pytest.raises(EgressDeniedError):
            self.ctrl.validate_url("http://127.0.0.1:8080/internal")

    def test_metadata_endpoint_blocked(self):
        """169.254.169.254 is a raw IP — blocked by default allowlist check."""
        with pytest.raises(EgressDeniedError):
            self.ctrl.validate_url("http://169.254.169.254/latest/meta-data/")

    def test_private_ip_blocked(self):
        with pytest.raises(EgressDeniedError):
            self.ctrl.validate_url("http://10.0.0.1:9000/bucket")


# ---------------------------------------------------------------------------
# get_proxy_config
# ---------------------------------------------------------------------------

class TestGetProxyConfig:
    """Proxy config: {} for internal, populated dict for external with proxy set."""

    def test_internal_no_proxy(self):
        ctrl = EgressController()
        config = ctrl.get_proxy_config("http://zovark-inference:8080/v1/chat")
        assert config == {}

    def test_internal_postgres_no_proxy(self):
        ctrl = EgressController()
        config = ctrl.get_proxy_config("http://postgres:5432")
        assert config == {}

    def test_external_with_proxy_url(self):
        ctrl = EgressController(proxy_url="http://squid:3128")
        config = ctrl.get_proxy_config("https://splunk.com/api")
        assert "http" in config or "https" in config
        assert "squid:3128" in config.get("http", "") or "squid:3128" in config.get("https", "")

    def test_external_without_proxy_returns_empty(self):
        """If no proxy is configured, get_proxy_config returns {} (with a warning)."""
        ctrl = EgressController(proxy_url="")
        config = ctrl.get_proxy_config("https://splunk.com/api")
        assert config == {}

    def test_dot_internal_no_proxy(self):
        ctrl = EgressController()
        config = ctrl.get_proxy_config("http://service.internal/path")
        assert config == {}


# ---------------------------------------------------------------------------
# is_internal
# ---------------------------------------------------------------------------

class TestIsInternal:

    def setup_method(self):
        self.ctrl = EgressController()

    @pytest.mark.parametrize("hostname", [
         "postgres", "redis", "temporal", "minio",
        "nats", "jaeger", "embedding-server", "localhost",
        "zovark-api", "pgbouncer",
    ])
    def test_known_internal_hosts(self, hostname):
        assert self.ctrl.is_internal(hostname) is True

    def test_dot_internal_suffix(self):
        assert self.ctrl.is_internal("my-service.internal") is True

    @pytest.mark.parametrize("hostname", [
        "splunk.com", "evil.com", "google.com", "api.crowdstrike.com",
    ])
    def test_external_not_internal(self, hostname):
        assert self.ctrl.is_internal(hostname) is False


# ---------------------------------------------------------------------------
# Custom allowed_domains
# ---------------------------------------------------------------------------

class TestCustomAllowedDomains:

    def test_custom_domain_allowed(self):
        ctrl = EgressController(allowed_domains={"custom-siem.corp"})
        assert ctrl.validate_url("https://custom-siem.corp/api") is True

    def test_default_domains_not_present_when_overridden(self):
        """Passing allowed_domains replaces (not extends) the default set."""
        ctrl = EgressController(allowed_domains={"custom-siem.corp"})
        with pytest.raises(EgressDeniedError):
            ctrl.validate_url("https://splunk.com/api")

    def test_subdomain_of_custom_allowed(self):
        ctrl = EgressController(allowed_domains={"corp.internal.example"})
        assert ctrl.validate_url("https://api.corp.internal.example/v1") is True
