"""Parsing tools — structured log parsing for various formats."""
import re


def parse_windows_event(raw_log: str) -> dict:
    """Parse Windows event log key=value pairs into dict."""
    if not raw_log:
        return {}
    # Limit parsing to first 4KB to prevent ReDoS on large payloads.
    # Key=value pairs appear in structured fields, not in long raw payloads.
    parse_input = raw_log[:4096] if len(raw_log) > 4096 else raw_log
    result = {}
    # Match Key=Value patterns (value may be quoted or unquoted)
    pattern = r'(\w+)\s*=\s*(?:"([^"]*?)"|(\S+))'
    for match in re.finditer(pattern, parse_input):
        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        result[key] = value
    # Also match "Key: Value" patterns (Windows event viewer format)
    # Key limited to 50 chars to prevent ReDoS on long word strings
    pattern2 = r'(\w[\w ]{0,48}\w)\s*:\s+(\S+)'
    for match in re.finditer(pattern2, parse_input):
        key = match.group(1).strip().replace(" ", "")
        value = match.group(2)
        if key not in result:
            result[key] = value
    return result


def parse_syslog(raw_log: str) -> dict:
    """Parse syslog format into: timestamp, hostname, process, pid, message."""
    if not raw_log:
        return {}

    # Standard syslog: "Mon DD HH:MM:SS hostname process[pid]: message"
    pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)(?:\[(\d+)\])?\s*:\s*(.*)'
    match = re.match(pattern, raw_log)
    if match:
        result = {
            "timestamp": match.group(1),
            "hostname": match.group(2),
            "process": match.group(3),
            "message": match.group(5),
        }
        if match.group(4):
            result["pid"] = match.group(4)
        return result

    # RFC 5424 syslog
    pattern2 = r'^<\d+>\d*\s*(\S+)\s+(\S+)\s+(\S+)\s+(\d+|-)\s+(.*)'
    match2 = re.match(pattern2, raw_log)
    if match2:
        return {
            "timestamp": match2.group(1),
            "hostname": match2.group(2),
            "process": match2.group(3),
            "pid": match2.group(4) if match2.group(4) != "-" else None,
            "message": match2.group(5),
        }

    return {}


def parse_auth_log(raw_log: str) -> dict:
    """Parse auth log: action (success/failure), username, source_ip, method."""
    if not raw_log:
        return {}

    result = {}

    # Determine action
    if re.search(r'(?:Failed|failure|denied|invalid|error)', raw_log, re.IGNORECASE):
        result["action"] = "failure"
    elif re.search(r'(?:Accepted|success|succeeded|authenticated)', raw_log, re.IGNORECASE):
        result["action"] = "success"

    # Extract username
    user_match = re.search(r'(?:for|user[= ])\s*(\w+)', raw_log, re.IGNORECASE)
    if user_match:
        result["username"] = user_match.group(1)

    # Extract source IP
    ip_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log)
    if ip_match:
        result["source_ip"] = ip_match.group(1)

    # Extract port
    port_match = re.search(r'port\s+(\d+)', raw_log)
    if port_match:
        result["port"] = port_match.group(1)

    # Extract method
    method_match = re.search(r'(password|publickey|keyboard-interactive|gssapi|ssh2)', raw_log, re.IGNORECASE)
    if method_match:
        result["method"] = method_match.group(1).lower()

    return result if result else {}


def parse_dns_query(raw_log: str) -> dict:
    """Parse DNS query logs: query_name, query_type, source_ip, response_size."""
    if not raw_log:
        return {}

    result = {}

    # Look for DNS-related content
    if not re.search(r'(?:dns|query|QueryType|QueryName|NXDOMAIN|NOERROR)', raw_log, re.IGNORECASE):
        return {}

    # Extract query name (domain)
    qname_match = re.search(r'(?:query|QueryName[= ])\s*(\S+)', raw_log, re.IGNORECASE)
    if qname_match:
        result["query_name"] = qname_match.group(1).rstrip(",;")
    else:
        # Try to find a domain-like pattern after "DNS"
        domain_match = re.search(r'DNS\s+(?:query\s+)?([a-zA-Z0-9][\w.\-]+\.[a-zA-Z]{2,})', raw_log, re.IGNORECASE)
        if domain_match:
            result["query_name"] = domain_match.group(1)

    # Extract query type
    qtype_match = re.search(r'QueryType\s*=\s*(\w+)', raw_log, re.IGNORECASE)
    if qtype_match:
        result["query_type"] = qtype_match.group(1)
    else:
        type_match = re.search(r'type\s*[:=]\s*(\w+)', raw_log, re.IGNORECASE)
        if type_match:
            result["query_type"] = type_match.group(1)

    # Extract source IP
    ip_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log)
    if ip_match:
        result["source_ip"] = ip_match.group(1)
    else:
        ip_match2 = re.search(r'(?:client|src|source)[= ]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log, re.IGNORECASE)
        if ip_match2:
            result["source_ip"] = ip_match2.group(1)

    # Extract response size
    size_match = re.search(r'ResponseSize\s*=\s*(\d+)', raw_log, re.IGNORECASE)
    if size_match:
        result["response_size"] = int(size_match.group(1))

    return result if result else {}


def parse_http_request(raw_log: str) -> dict:
    """Parse HTTP log: method, path, status_code, source_ip, user_agent."""
    if not raw_log:
        return {}

    result = {}

    # Common Log Format / Combined Log Format
    clf_match = re.match(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+)',
        raw_log,
    )
    if clf_match:
        result["source_ip"] = clf_match.group(1)
        result["timestamp"] = clf_match.group(2)
        result["method"] = clf_match.group(3)
        result["path"] = clf_match.group(4)
        result["status_code"] = int(clf_match.group(5))
        result["response_size"] = int(clf_match.group(6))

        # Extract user agent
        ua_match = re.search(r'"([^"]*)"$', raw_log)
        if ua_match:
            result["user_agent"] = ua_match.group(1)
        return result

    # Fallback: try to extract HTTP method + path
    method_match = re.search(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', raw_log)
    if method_match:
        result["method"] = method_match.group(1)
        result["path"] = method_match.group(2)

    # Status code
    status_match = re.search(r'\b(\d{3})\b', raw_log)
    if status_match and method_match:
        result["status_code"] = int(status_match.group(1))

    # Source IP at start of line
    ip_match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log)
    if ip_match:
        result["source_ip"] = ip_match.group(1)

    return result if result else {}
