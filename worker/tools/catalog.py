"""Tool catalog — maps tool names to functions, descriptions, and argument types."""

from tools import extraction, analysis, parsing, scoring, detection, enrichment

TOOL_CATALOG = {
    # --- Extraction (8 tools) ---
    "extract_ipv4": {"function": extraction.extract_ipv4, "category": "extraction", "description": "Extract IPv4 addresses from text with evidence_refs", "args": {"text": str}},
    "extract_ipv6": {"function": extraction.extract_ipv6, "category": "extraction", "description": "Extract IPv6 addresses from text", "args": {"text": str}},
    "extract_domains": {"function": extraction.extract_domains, "category": "extraction", "description": "Extract domain names with TLD validation", "args": {"text": str}},
    "extract_urls": {"function": extraction.extract_urls, "category": "extraction", "description": "Extract full URLs (http/https/ftp) from text", "args": {"text": str}},
    "extract_hashes": {"function": extraction.extract_hashes, "category": "extraction", "description": "Extract MD5/SHA1/SHA256 hashes from text", "args": {"text": str}},
    "extract_emails": {"function": extraction.extract_emails, "category": "extraction", "description": "Extract email addresses from text", "args": {"text": str}},
    "extract_usernames": {"function": extraction.extract_usernames, "category": "extraction", "description": "Extract usernames from SIEM patterns", "args": {"text": str}},
    "extract_cves": {"function": extraction.extract_cves, "category": "extraction", "description": "Extract CVE identifiers from text", "args": {"text": str}},

    # --- Analysis (4 tools) ---
    "count_pattern": {"function": analysis.count_pattern, "category": "analysis", "description": "Count regex pattern matches in text", "args": {"text": str, "pattern": str}},
    "calculate_entropy": {"function": analysis.calculate_entropy, "category": "analysis", "description": "Shannon entropy of a string", "args": {"text": str}},
    "detect_encoding": {"function": analysis.detect_encoding, "category": "analysis", "description": "Detect base64, hex, or URL encoding in text", "args": {"text": str}},
    "check_base64": {"function": analysis.check_base64, "category": "analysis", "description": "Find and decode base64 strings in text", "args": {"text": str}},

    # --- Parsing (5 tools) ---
    "parse_windows_event": {"function": parsing.parse_windows_event, "category": "parsing", "description": "Parse Windows event log key=value pairs", "args": {"raw_log": str}},
    "parse_syslog": {"function": parsing.parse_syslog, "category": "parsing", "description": "Parse syslog format into structured fields", "args": {"raw_log": str}},
    "parse_auth_log": {"function": parsing.parse_auth_log, "category": "parsing", "description": "Parse auth log: action, username, source_ip, method", "args": {"raw_log": str}},
    "parse_dns_query": {"function": parsing.parse_dns_query, "category": "parsing", "description": "Parse DNS query logs into structured fields", "args": {"raw_log": str}},
    "parse_http_request": {"function": parsing.parse_http_request, "category": "parsing", "description": "Parse HTTP log: method, path, status_code, source_ip", "args": {"raw_log": str}},

    # --- Scoring (6 tools) ---
    "score_brute_force": {"function": scoring.score_brute_force, "category": "scoring", "description": "Risk score for brute force attacks", "args": {"failed_count": int, "unique_sources": int, "timespan_minutes": int}},
    "score_phishing": {"function": scoring.score_phishing, "category": "scoring", "description": "Risk score for phishing", "args": {"url_count": int, "suspicious_domains": int, "has_credential_form": bool, "has_urgency_language": bool}},
    "score_lateral_movement": {"function": scoring.score_lateral_movement, "category": "scoring", "description": "Risk score for lateral movement", "args": {"method": str, "is_admin_share": bool, "is_remote_exec": bool, "uses_pass_the_hash": bool}},
    "score_exfiltration": {"function": scoring.score_exfiltration, "category": "scoring", "description": "Risk score for data exfiltration", "args": {"bytes_transferred": int, "is_external_dest": bool, "is_off_hours": bool, "is_encrypted": bool}},
    "score_c2_beacon": {"function": scoring.score_c2_beacon, "category": "scoring", "description": "Risk score for C2 beaconing", "args": {"interval_stddev": float, "avg_interval_seconds": float, "connection_count": int, "domain_entropy": float}},
    "score_generic": {"function": scoring.score_generic, "category": "scoring", "description": "Generic risk score based on indicator counts", "args": {"indicators_found": int, "high_severity_count": int, "medium_severity_count": int}},

    # --- Detection (11 tools) ---
    "detect_kerberoasting": {"function": detection.detect_kerberoasting, "category": "detection", "description": "Detect Kerberoasting: RC4, TGS requests, SPN abuse", "args": {"siem_event": dict}},
    "detect_golden_ticket": {"function": detection.detect_golden_ticket, "category": "detection", "description": "Detect Golden Ticket: forged TGT, abnormal lifetime", "args": {"siem_event": dict}},
    "detect_ransomware": {"function": detection.detect_ransomware, "category": "detection", "description": "Detect ransomware: shadow copy deletion, mass encryption", "args": {"siem_event": dict}},
    "detect_phishing": {"function": detection.detect_phishing, "category": "detection", "description": "Detect phishing: suspicious URLs, credential harvesting", "args": {"siem_event": dict}},
    "detect_c2": {"function": detection.detect_c2, "category": "detection", "description": "Detect C2: beacon intervals, DGA domains, encoded payloads", "args": {"siem_event": dict}},
    "detect_data_exfil": {"function": detection.detect_data_exfil, "category": "detection", "description": "Detect data exfiltration: large transfers, off-hours", "args": {"siem_event": dict}},
    "detect_lolbin_abuse": {"function": detection.detect_lolbin_abuse, "category": "detection", "description": "Detect LOLBin abuse: certutil, mshta, bitsadmin", "args": {"siem_event": dict}},
    "detect_com_hijacking": {"function": detection.detect_com_hijacking, "category": "detection", "description": "Detect COM hijacking via registry modifications", "args": {"siem_event": dict}},
    "detect_encoded_service": {"function": detection.detect_encoded_service, "category": "detection", "description": "Detect malicious services with encoded commands", "args": {"siem_event": dict}},
    "detect_token_impersonation": {"function": detection.detect_token_impersonation, "category": "detection", "description": "Detect token impersonation via RunAs", "args": {"siem_event": dict}},
    "detect_appcert_dlls": {"function": detection.detect_appcert_dlls, "category": "detection", "description": "Detect AppCert DLLs persistence", "args": {"siem_event": dict}},
    "detect_dns_exfiltration": {"function": detection.detect_dns_exfiltration, "category": "detection", "description": "Detect DNS exfiltration: high-entropy subdomains, TXT abuse, high volume", "args": {"siem_event": dict}},
    "detect_credential_access": {"function": detection.detect_credential_access, "category": "detection", "description": "Detect credential access: LSASS dump, mimikatz, SAM extraction, DCSync", "args": {"siem_event": dict}},
    "detect_supply_chain": {"function": detection.detect_supply_chain, "category": "detection", "description": "Detect supply chain compromise: package tampering, hash mismatch, CI/CD compromise", "args": {"siem_event": dict}},

    # --- Enrichment (4 tools) ---
    "map_mitre": {"function": enrichment.map_mitre, "category": "enrichment", "description": "Map MITRE ATT&CK technique IDs to names and tactics", "args": {"technique_ids": list}},
    "lookup_known_bad": {"function": enrichment.lookup_known_bad, "category": "enrichment", "description": "Check IOC against local known-bad list", "args": {"value": str, "ioc_type": str}},
    "correlate_with_history": {"function": enrichment.correlate_with_history, "category": "enrichment", "description": "Check if IOCs appeared in recent investigations", "args": {"ioc_values": list, "lookback_hours": int, "history_context": dict}},
    "lookup_institutional_knowledge": {"function": enrichment.lookup_institutional_knowledge, "category": "enrichment", "description": "Check entities against analyst-provided baselines", "args": {"entities": list, "knowledge_base": dict}},
}


def get_catalog_text() -> str:
    """Format catalog for injection into LLM prompt."""
    lines = []
    for name, info in sorted(TOOL_CATALOG.items()):
        args_str = ", ".join(f"{k}: {v.__name__}" for k, v in info["args"].items())
        lines.append(f"- {name}({args_str}) -- {info['description']}")
    return "\n".join(lines)


def get_tool_function(name: str):
    """Get tool function by name. Returns None if not found."""
    entry = TOOL_CATALOG.get(name)
    return entry["function"] if entry else None
