"""
Remediation Engine — deterministic suggestion + verification.

Suggests remediation actions based on attack_type + historical success.
Verification submits a synthetic alert of the same type and compares verdict.

Circuit breaker: MAX_VERIFICATION_ATTEMPTS = 3 per attack_type per 24h
Rate limiter:   MAX_SYNTHETIC_PER_HOUR = 10 per tenant
Kill switch:    system_configs 'remediation.auto_verify_enabled' (default false)
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

MAX_VERIFICATION_ATTEMPTS = 3
MAX_SYNTHETIC_PER_HOUR = 10

# ── Deterministic remediation rules ──────────────────────────

REMEDIATION_RULES: dict[str, list[dict]] = {
    "brute_force": [
        {"action_type": "block", "description": "Block source IP at perimeter firewall", "priority": 90},
        {"action_type": "access_revoke", "description": "Reset credentials for targeted accounts", "priority": 85},
        {"action_type": "rule_update", "description": "Lower brute-force lockout threshold in SIEM", "priority": 60},
    ],
    "phishing_investigation": [
        {"action_type": "block", "description": "Block sender domain and phishing URLs at email gateway", "priority": 90},
        {"action_type": "access_revoke", "description": "Reset credentials for recipients who clicked", "priority": 85},
        {"action_type": "investigate_further", "description": "Check mail logs for other recipients of same campaign", "priority": 70},
    ],
    "ransomware_triage": [
        {"action_type": "isolate", "description": "Isolate affected host from network immediately", "priority": 95},
        {"action_type": "block", "description": "Block C2 IPs/domains at firewall", "priority": 90},
        {"action_type": "investigate_further", "description": "Check shadow copy status and lateral movement indicators", "priority": 80},
    ],
    "data_exfiltration_detection": [
        {"action_type": "block", "description": "Block destination IPs/domains involved in data transfer", "priority": 90},
        {"action_type": "isolate", "description": "Isolate source host to prevent further exfiltration", "priority": 85},
        {"action_type": "access_revoke", "description": "Revoke cloud storage tokens used for exfil", "priority": 80},
    ],
    "privilege_escalation_hunt": [
        {"action_type": "access_revoke", "description": "Revoke escalated privileges and reset account", "priority": 90},
        {"action_type": "config_change", "description": "Harden UAC/sudo configuration on affected host", "priority": 75},
        {"action_type": "investigate_further", "description": "Check for persistence mechanisms installed post-escalation", "priority": 70},
    ],
    "c2_communication_hunt": [
        {"action_type": "isolate", "description": "Isolate beaconing host from network", "priority": 95},
        {"action_type": "block", "description": "Block C2 domains/IPs at DNS and firewall", "priority": 90},
        {"action_type": "investigate_further", "description": "Hunt for other hosts beaconing to same C2 infrastructure", "priority": 80},
    ],
    "lateral_movement_detection": [
        {"action_type": "isolate", "description": "Isolate compromised host to stop lateral spread", "priority": 95},
        {"action_type": "access_revoke", "description": "Disable compromised service accounts used for movement", "priority": 90},
        {"action_type": "rule_update", "description": "Add detection for observed lateral movement technique", "priority": 65},
    ],
    "insider_threat_detection": [
        {"action_type": "access_revoke", "description": "Restrict user access pending HR review", "priority": 85},
        {"action_type": "investigate_further", "description": "Review full access logs for data staging patterns", "priority": 80},
        {"action_type": "config_change", "description": "Enable enhanced logging on sensitive data repositories", "priority": 60},
    ],
    "kerberoasting": [
        {"action_type": "access_revoke", "description": "Reset service account passwords (use 25+ char random)", "priority": 90},
        {"action_type": "config_change", "description": "Migrate SPNs to AES-only (disable RC4)", "priority": 85},
        {"action_type": "rule_update", "description": "Alert on RC4 TGS requests for non-krbtgt SPNs", "priority": 70},
    ],
    "golden_ticket": [
        {"action_type": "access_revoke", "description": "Reset krbtgt password TWICE to invalidate forged tickets", "priority": 95},
        {"action_type": "investigate_further", "description": "Audit all domain controller access for last 7 days", "priority": 85},
        {"action_type": "config_change", "description": "Enable Protected Users group for privileged accounts", "priority": 75},
    ],
    "dcsync": [
        {"action_type": "access_revoke", "description": "Remove replication rights from compromised account", "priority": 95},
        {"action_type": "access_revoke", "description": "Reset krbtgt and all privileged account passwords", "priority": 90},
        {"action_type": "investigate_further", "description": "Check for persistence via DSRM password or AdminSDHolder", "priority": 80},
    ],
    "dll_sideloading": [
        {"action_type": "block", "description": "Quarantine malicious DLL and host binary", "priority": 90},
        {"action_type": "config_change", "description": "Enable DLL search order hardening (SafeDllSearchMode)", "priority": 75},
        {"action_type": "rule_update", "description": "Add hash-based detection for observed sideloaded DLL", "priority": 70},
    ],
    "lolbin_abuse": [
        {"action_type": "block", "description": "Block LOLBin execution via AppLocker/WDAC policy", "priority": 85},
        {"action_type": "investigate_further", "description": "Check for downloaded payloads and persistence", "priority": 80},
        {"action_type": "rule_update", "description": "Add command-line monitoring for observed LOLBin abuse pattern", "priority": 70},
    ],
    "process_injection": [
        {"action_type": "isolate", "description": "Isolate host with active process injection", "priority": 95},
        {"action_type": "investigate_further", "description": "Memory dump target process for payload analysis", "priority": 85},
        {"action_type": "config_change", "description": "Enable Credential Guard to protect lsass", "priority": 75},
    ],
    "dns_exfiltration": [
        {"action_type": "block", "description": "Block high-entropy DNS queries to identified exfil domain", "priority": 90},
        {"action_type": "config_change", "description": "Enable DNS query logging and entropy-based alerting", "priority": 75},
        {"action_type": "investigate_further", "description": "Quantify exfiltrated data volume from DNS query logs", "priority": 70},
    ],
    "powershell_obfuscation": [
        {"action_type": "block", "description": "Block encoded PowerShell execution via constrained language mode", "priority": 85},
        {"action_type": "investigate_further", "description": "Decode and analyze obfuscated payload", "priority": 80},
        {"action_type": "config_change", "description": "Enable PowerShell ScriptBlock logging and AMSI", "priority": 70},
    ],
    "network_beaconing": [
        {"action_type": "block", "description": "Block beacon destination at firewall and DNS sinkhole", "priority": 90},
        {"action_type": "isolate", "description": "Isolate beaconing host pending investigation", "priority": 85},
        {"action_type": "investigate_further", "description": "Analyze beacon pattern for C2 framework identification", "priority": 75},
    ],
    "cloud_infrastructure_attack": [
        {"action_type": "access_revoke", "description": "Rotate compromised IAM keys and revoke sessions", "priority": 95},
        {"action_type": "config_change", "description": "Enable MFA on all IAM accounts and restrict API access", "priority": 85},
        {"action_type": "investigate_further", "description": "Review CloudTrail for resource creation and data access", "priority": 80},
    ],
    "supply_chain_compromise": [
        {"action_type": "block", "description": "Quarantine compromised package and block its hash", "priority": 90},
        {"action_type": "investigate_further", "description": "Audit all systems that installed the compromised package", "priority": 85},
        {"action_type": "config_change", "description": "Pin package versions and enable hash verification in CI/CD", "priority": 75},
    ],
    "wmi_lateral": [
        {"action_type": "isolate", "description": "Isolate source and target hosts of WMI lateral movement", "priority": 90},
        {"action_type": "access_revoke", "description": "Disable account used for remote WMI execution", "priority": 85},
        {"action_type": "config_change", "description": "Restrict WMI remote access via GPO firewall rules", "priority": 70},
    ],
    "rdp_tunneling": [
        {"action_type": "block", "description": "Block SSH tunnel source and unusual RDP ports at firewall", "priority": 90},
        {"action_type": "access_revoke", "description": "Disable accounts used for tunnel establishment", "priority": 85},
        {"action_type": "config_change", "description": "Restrict RDP to jump hosts only via network segmentation", "priority": 75},
    ],
    "credential_access": [
        {"action_type": "access_revoke", "description": "Reset all credentials on affected systems", "priority": 95},
        {"action_type": "isolate", "description": "Isolate host where credential dumping occurred", "priority": 90},
        {"action_type": "config_change", "description": "Enable Credential Guard and restrict debug privileges", "priority": 80},
    ],
    "api_key_abuse": [
        {"action_type": "access_revoke", "description": "Rotate compromised API keys immediately", "priority": 95},
        {"action_type": "block", "description": "Block source IPs performing unauthorized API calls", "priority": 85},
        {"action_type": "config_change", "description": "Enforce API key scoping and rate limiting", "priority": 70},
    ],
}

# Fallback for unknown attack types
_DEFAULT_RULES = [
    {"action_type": "investigate_further", "description": "Conduct deeper investigation into this alert type", "priority": 70},
    {"action_type": "rule_update", "description": "Review and update detection rules for this alert category", "priority": 50},
]


@dataclass
class VerificationState:
    """Tracks verification attempts per attack_type per tenant."""
    attempts: dict[str, list[float]] = field(default_factory=dict)
    synthetic_timestamps: list[float] = field(default_factory=list)

    def _key(self, attack_type: str) -> str:
        return attack_type

    def can_verify(self, attack_type: str) -> tuple[bool, str]:
        """Check circuit breaker: max 3 attempts per type in 24h."""
        now = time.time()
        cutoff = now - 86400  # 24 hours

        key = self._key(attack_type)
        if key in self.attempts:
            recent = [t for t in self.attempts[key] if t > cutoff]
            self.attempts[key] = recent
            if len(recent) >= MAX_VERIFICATION_ATTEMPTS:
                return False, f"circuit breaker open: {len(recent)}/{MAX_VERIFICATION_ATTEMPTS} attempts for {attack_type} in 24h"

        return True, ""

    def can_submit_synthetic(self) -> tuple[bool, str]:
        """Check rate limiter: max 10 synthetic alerts per hour."""
        now = time.time()
        cutoff = now - 3600  # 1 hour

        recent = [t for t in self.synthetic_timestamps if t > cutoff]
        self.synthetic_timestamps = recent
        if len(recent) >= MAX_SYNTHETIC_PER_HOUR:
            return False, f"rate limit: {len(recent)}/{MAX_SYNTHETIC_PER_HOUR} synthetic alerts this hour"

        return True, ""

    def record_attempt(self, attack_type: str) -> None:
        now = time.time()
        key = self._key(attack_type)
        if key not in self.attempts:
            self.attempts[key] = []
        self.attempts[key].append(now)

    def record_synthetic(self) -> None:
        self.synthetic_timestamps.append(time.time())


# Per-tenant verification state (in-memory, resets on worker restart)
_tenant_states: dict[str, VerificationState] = {}


def _get_state(tenant_id: str) -> VerificationState:
    if tenant_id not in _tenant_states:
        _tenant_states[tenant_id] = VerificationState()
    return _tenant_states[tenant_id]


def suggest_actions(
    attack_type: str,
    risk_score: int,
    verdict: str,
    iocs: Optional[list[dict]] = None,
) -> list[dict]:
    """Return deterministic remediation suggestions for an attack type.

    Adjusts priority based on risk_score and verdict.
    """
    if verdict == "benign":
        return [{"action_type": "false_positive", "description": "Investigation concluded benign — no action required", "priority": 10}]

    if verdict == "inconclusive":
        return [{"action_type": "investigate_further", "description": "Verdict inconclusive — requires analyst deep-dive", "priority": 80}]

    rules = REMEDIATION_RULES.get(attack_type, _DEFAULT_RULES)

    suggestions = []
    for rule in rules:
        adjusted_priority = rule["priority"]

        # Boost priority for critical-risk investigations
        if risk_score >= 90:
            adjusted_priority = min(100, adjusted_priority + 10)
        elif risk_score >= 70:
            adjusted_priority = min(100, adjusted_priority + 5)
        # Lower priority for low-confidence verdicts
        elif risk_score < 50:
            adjusted_priority = max(10, adjusted_priority - 15)

        # Boost if IOCs are present (concrete evidence)
        if iocs and len(iocs) >= 3:
            adjusted_priority = min(100, adjusted_priority + 5)

        suggestions.append({
            "action_type": rule["action_type"],
            "description": rule["description"],
            "priority": adjusted_priority,
        })

    return sorted(suggestions, key=lambda x: x["priority"], reverse=True)


def check_circuit_breaker(tenant_id: str, attack_type: str) -> tuple[bool, str]:
    """Check if verification is allowed (circuit breaker + rate limiter)."""
    state = _get_state(tenant_id)

    ok, msg = state.can_verify(attack_type)
    if not ok:
        return False, msg

    ok, msg = state.can_submit_synthetic()
    if not ok:
        return False, msg

    return True, ""


def record_verification(tenant_id: str, attack_type: str) -> None:
    """Record a verification attempt for circuit breaker tracking."""
    state = _get_state(tenant_id)
    state.record_attempt(attack_type)
    state.record_synthetic()


def get_verification_stats(tenant_id: str) -> dict:
    """Return current circuit breaker state for a tenant."""
    state = _get_state(tenant_id)
    now = time.time()
    cutoff_24h = now - 86400
    cutoff_1h = now - 3600

    per_type = {}
    for atype, timestamps in state.attempts.items():
        recent = [t for t in timestamps if t > cutoff_24h]
        per_type[atype] = {
            "attempts_24h": len(recent),
            "max": MAX_VERIFICATION_ATTEMPTS,
            "open": len(recent) >= MAX_VERIFICATION_ATTEMPTS,
        }

    recent_synthetic = [t for t in state.synthetic_timestamps if t > cutoff_1h]
    return {
        "per_type": per_type,
        "synthetic_hour": len(recent_synthetic),
        "synthetic_max": MAX_SYNTHETIC_PER_HOUR,
        "rate_limited": len(recent_synthetic) >= MAX_SYNTHETIC_PER_HOUR,
    }
