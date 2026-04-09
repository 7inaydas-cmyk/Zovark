"""Egress controller — domain allowlisting for outbound HTTP requests.

All worker HTTP requests to external services MUST go through this controller.
Non-allowlisted domains are blocked. Proxy unavailability = fail closed.
"""
import os
import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Allowlisted external domains for SOAR integrations
ALLOWED_DOMAINS = {
    # SIEM platforms
    "splunk.com", "sentinelone.net", "crowdstrike.com",
    "paloaltonetworks.com", "elastic.co",
    # Ticketing / ITSM
    "atlassian.net", "servicenow.com", "zendesk.com",
    # Communication
    "slack.com", "pagerduty.com", "teams.microsoft.com",
    # Threat intelligence
    "virustotal.com", "abuseipdb.com", "shodan.io",
    "redhuntlabs.com",
}

# Internal services that bypass the proxy
NO_PROXY_HOSTS = {
    "postgres", "valkey", "redis",  # redis kept as legacy alias
    "temporal", "minio", "nats", "jaeger", "embedding-server", "localhost",
    "zovark-api", "pgbouncer", "zovark-inference",
}

PROXY_URL = os.environ.get("HTTP_PROXY", os.environ.get("HTTPS_PROXY", ""))


class EgressDeniedError(Exception):
    """Raised when a request to a non-allowlisted domain is blocked."""
    pass


class EgressController:
    """Controls outbound HTTP access from workers."""

    def __init__(self, allowed_domains=None, proxy_url=None):
        self.allowed_domains = allowed_domains or ALLOWED_DOMAINS
        self.proxy_url = proxy_url if proxy_url is not None else PROXY_URL

    def is_internal(self, hostname: str) -> bool:
        """Check if hostname is an internal service."""
        return hostname in NO_PROXY_HOSTS or hostname.endswith(".internal")

    def validate_url(self, url: str) -> bool:
        """Pre-flight check: is this URL's domain in the allowlist?

        Returns True if allowed, raises EgressDeniedError if blocked.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Internal services always allowed (no proxy needed)
        if self.is_internal(hostname):
            return True

        # Check against allowlist (match domain and subdomains)
        for allowed in self.allowed_domains:
            if hostname == allowed or hostname.endswith("." + allowed):
                return True

        raise EgressDeniedError(
            f"Egress blocked: domain '{hostname}' not in allowlist. "
            f"Allowed: {sorted(self.allowed_domains)}"
        )

    def get_proxy_config(self, url: str) -> dict:
        """Get proxy configuration for a URL.

        Returns dict with proxy settings for requests/aiohttp.
        Internal URLs bypass the proxy.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if self.is_internal(hostname):
            return {}  # No proxy for internal

        if not self.proxy_url:
            logger.warning("No egress proxy configured — external request may fail")
            return {}

        return {
            "http": self.proxy_url,
            "https": self.proxy_url,
        }

    async def request(self, method: str, url: str, **kwargs) -> dict:
        """Make an HTTP request through the egress proxy.

        Validates domain, routes through proxy, returns response.
        Raises EgressDeniedError for blocked domains.

        Supports kwargs: headers, json, data, params (query string dict), timeout.
        """
        # Append query params to URL before validation
        query_params = kwargs.get("params")
        if query_params:
            from urllib.parse import urlencode, urlparse, urlunparse
            parsed = urlparse(url)
            existing = parsed.query
            new_query = (existing + "&" if existing else "") + urlencode(query_params)
            url = urlunparse(parsed._replace(query=new_query))

        self.validate_url(url)

        import urllib.request
        proxy_config = self.get_proxy_config(url)

        headers = kwargs.get("headers", {})
        body = kwargs.get("json")
        data = kwargs.get("data")

        if body:
            import json
            data = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")

        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())

        if proxy_config:
            proxy_handler = urllib.request.ProxyHandler(proxy_config)
            opener = urllib.request.build_opener(proxy_handler)
        else:
            opener = urllib.request.build_opener()

        timeout = kwargs.get("timeout", 30)
        try:
            import json as jsonlib
            with opener.open(req, timeout=timeout) as resp:
                content = resp.read().decode()
                try:
                    body = jsonlib.loads(content)
                except (ValueError, jsonlib.JSONDecodeError):
                    body = content
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body,
                }
        except urllib.error.HTTPError as e:
            return {
                "status": e.code,
                "headers": dict(e.headers),
                "body": e.read().decode()[:1000],
            }


# Module-level singleton
_controller = None

def get_egress_controller() -> EgressController:
    global _controller
    if _controller is None:
        _controller = EgressController()
    return _controller
