"""Task-type to tool subset mapping for LLM prompt optimization.

Reduces the tool catalog from 40 to 8-12 relevant tools per task type.
Improves:
  - Prefill speed: ~500 fewer input tokens
  - Decision quality: smaller search space on small models
  - KV cache usage: more headroom for concurrent requests

Fallback: unknown task types get the full catalog.
Every tool in investigation_plans.json for a given type MUST be in that type's subset.
"""

TOOL_SUBSETS = {
    "brute_force": [
        "parse_auth_log", "extract_ipv4", "extract_usernames",
        "count_pattern", "score_brute_force",
        "correlate_with_history", "map_mitre",
    ],
    "phishing_investigation": [
        "extract_urls", "extract_domains", "extract_emails",
        "detect_phishing", "count_pattern", "score_phishing",
        "lookup_known_bad", "correlate_with_history", "map_mitre",
    ],
    "ransomware_triage": [
        "parse_windows_event", "extract_ipv4", "extract_hashes",
        "detect_ransomware", "count_pattern",
        "lookup_known_bad", "correlate_with_history", "map_mitre",
    ],
    "data_exfiltration_detection": [
        "extract_ipv4", "extract_domains", "extract_urls",
        "detect_encoding", "detect_data_exfil", "score_exfiltration",
        "correlate_with_history", "map_mitre",
    ],
    "privilege_escalation_hunt": [
        "parse_auth_log", "extract_usernames", "extract_ipv4",
        "count_pattern", "detect_com_hijacking", "detect_token_impersonation",
        "detect_appcert_dlls", "score_generic",
        "correlate_with_history", "map_mitre",
    ],
    "c2_communication_hunt": [
        "extract_ipv4", "extract_domains", "calculate_entropy",
        "detect_c2", "score_c2_beacon",
        "lookup_known_bad", "correlate_with_history", "map_mitre",
    ],
    "lateral_movement_detection": [
        "parse_windows_event", "extract_ipv4", "extract_usernames",
        "count_pattern", "detect_encoded_service",
        "score_lateral_movement", "correlate_with_history", "map_mitre",
    ],
    "insider_threat_detection": [
        "extract_usernames", "extract_ipv4", "extract_emails",
        "count_pattern", "detect_data_exfil", "score_exfiltration",
        "lookup_institutional_knowledge", "map_mitre",
    ],
    "network_beaconing": [
        "extract_ipv4", "extract_domains", "parse_dns_query",
        "calculate_entropy", "detect_c2", "score_c2_beacon",
        "correlate_with_history", "map_mitre",
    ],
    "cloud_infrastructure_attack": [
        "extract_ipv4", "extract_usernames", "extract_emails",
        "count_pattern", "score_generic",
        "lookup_known_bad", "correlate_with_history", "map_mitre",
    ],
    "supply_chain_compromise": [
        "extract_hashes", "extract_domains", "extract_urls",
        "detect_supply_chain", "lookup_known_bad",
        "correlate_with_history", "map_mitre",
    ],
    "kerberoasting": [
        "parse_windows_event", "extract_usernames", "extract_ipv4",
        "detect_kerberoasting", "count_pattern",
        "correlate_with_history", "map_mitre",
    ],
    "golden_ticket": [
        "parse_windows_event", "extract_usernames", "extract_ipv4",
        "detect_golden_ticket", "count_pattern",
        "correlate_with_history", "map_mitre",
    ],
    "dcsync": [
        "parse_windows_event", "extract_ipv4", "extract_usernames",
        "count_pattern", "score_generic",
        "correlate_with_history", "map_mitre",
    ],
    "dll_sideloading": [
        "parse_windows_event", "extract_hashes", "extract_ipv4",
        "count_pattern", "lookup_known_bad", "score_generic",
        "correlate_with_history", "map_mitre",
    ],
    "lolbin_abuse": [
        "parse_windows_event", "extract_ipv4", "extract_urls",
        "detect_lolbin_abuse", "detect_powershell_obfuscation",
        "correlate_with_history", "map_mitre",
    ],
    "process_injection": [
        "parse_windows_event", "extract_ipv4", "extract_hashes",
        "count_pattern", "score_generic",
        "lookup_known_bad", "correlate_with_history", "map_mitre",
    ],
    "wmi_lateral": [
        "parse_windows_event", "extract_ipv4", "extract_usernames",
        "count_pattern", "score_lateral_movement",
        "correlate_with_history", "map_mitre",
    ],
    "rdp_tunneling": [
        "extract_ipv4", "extract_usernames", "parse_auth_log",
        "count_pattern", "score_generic",
        "lookup_known_bad", "correlate_with_history", "map_mitre",
    ],
    "dns_exfiltration": [
        "parse_dns_query", "extract_domains", "extract_ipv4",
        "detect_dns_exfiltration", "count_pattern",
        "correlate_with_history", "map_mitre",
    ],
    "powershell_obfuscation": [
        "parse_windows_event", "detect_powershell_obfuscation",
        "check_base64", "detect_encoding",
        "detect_lolbin_abuse",
        "correlate_with_history", "map_mitre",
    ],
    "credential_access": [
        "parse_auth_log", "extract_usernames", "extract_ipv4",
        "detect_credential_access", "extract_hashes",
        "correlate_with_history", "map_mitre",
    ],
    "api_key_abuse": [
        "extract_ipv4", "extract_emails", "parse_http_request",
        "count_pattern", "lookup_known_bad", "score_generic",
        "correlate_with_history", "map_mitre",
    ],
    "benign_system_event": [
        "extract_ipv4", "score_generic",
    ],
}

# Aliases — map SIEM task_types to canonical plan names
ALIASES = {
    "phishing": "phishing_investigation",
    "ransomware": "ransomware_triage",
    "data_exfiltration": "data_exfiltration_detection",
    "data_exfil": "data_exfiltration_detection",
    "exfiltration": "data_exfiltration_detection",
    "privilege_escalation": "privilege_escalation_hunt",
    "priv_esc": "privilege_escalation_hunt",
    "c2": "c2_communication_hunt",
    "c2_beacon": "c2_communication_hunt",
    "c2_communication": "c2_communication_hunt",
    "command_and_control": "c2_communication_hunt",
    "lateral_movement": "lateral_movement_detection",
    "insider_threat": "insider_threat_detection",
    "beaconing": "network_beaconing",
    "cloud_attack": "cloud_infrastructure_attack",
    "supply_chain": "supply_chain_compromise",
    "credential_dump": "credential_access",
    "dll_sideload": "dll_sideloading",
    "lolbin": "lolbin_abuse",
    "dns_exfil": "dns_exfiltration",
    "powershell_obfusc": "powershell_obfuscation",
}


def get_tool_subset(task_type: str):
    """Get relevant tool names for a task type. Returns None if unknown."""
    normalized = task_type.lower().strip().replace("-", "_")
    canonical = ALIASES.get(normalized, normalized)
    return TOOL_SUBSETS.get(canonical)


def get_subset_catalog_text(task_type: str):
    """Get formatted catalog text for a tool subset. Returns None if unknown."""
    from tools.catalog import TOOL_CATALOG

    subset_names = get_tool_subset(task_type)
    if subset_names is None:
        return None

    lines = []
    for name in subset_names:
        entry = TOOL_CATALOG.get(name)
        if entry:
            args_str = ", ".join(f"{k}: {v.__name__}" for k, v in entry["args"].items())
            lines.append(f"- {name}({args_str}) -- {entry['description']}")
    return "\n".join(lines)
