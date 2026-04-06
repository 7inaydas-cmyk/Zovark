"""
Attack Path Correlator — deterministic correlation across investigations.

Triggered by DB NOTIFY attack_path_correlate after Stage 5 STORE.
Does NOT modify investigation_workflow.py.

5 correlation rules:
1. Same source IP within 24h window
2. Same target user across alert types (48h)
3. Same host with escalating severity (12h)
4. IOC overlap across investigations (72h)
5. MITRE ATT&CK kill chain phase progression (168h)

Confidence scoring: 4-signal weighted average.
MIN_CONFIDENCE = 0.75 (below = dropped).
Failures → DLQ with 3 retries (1min, 5min, 15min backoff).
"""
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

MIN_CONFIDENCE = 0.75
MAX_PATHS_PER_DAY_COMMUNITY = 50
MAX_PATHS_PER_DAY_ENTERPRISE = 2000
DLQ_RETRY_BACKOFFS = [60, 300, 900]  # 1min, 5min, 15min

# MITRE kill chain phases in order
KILL_CHAIN_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# Map common technique prefixes to kill chain phases
TECHNIQUE_TO_PHASE = {
    "T1595": "reconnaissance", "T1592": "reconnaissance",
    "T1566": "initial-access", "T1190": "initial-access",
    "T1059": "execution", "T1053": "execution",
    "T1547": "persistence", "T1543": "persistence",
    "T1548": "privilege-escalation", "T1134": "privilege-escalation",
    "T1027": "defense-evasion", "T1070": "defense-evasion",
    "T1110": "credential-access", "T1558": "credential-access",
    "T1003": "credential-access",
    "T1021": "lateral-movement", "T1570": "lateral-movement",
    "T1560": "collection",
    "T1071": "command-and-control", "T1095": "command-and-control",
    "T1048": "exfiltration", "T1041": "exfiltration",
    "T1486": "impact", "T1490": "impact",
}


def _get_db():
    from settings import settings as _s
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", _s.database_url)
    )


def _get_technique_phase(technique_id: str) -> Optional[str]:
    """Map MITRE technique ID to kill chain phase."""
    prefix = technique_id.split(".")[0] if technique_id else ""
    return TECHNIQUE_TO_PHASE.get(prefix)


@dataclass
class CorrelationMatch:
    rule: str
    investigations: list[str]
    confidence: float
    chain_type: str
    mitre_chain: list[str] = field(default_factory=list)
    time_span_hours: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


# ── Correlation Rules ─────────────────────────────────────

def _rule_same_source_ip(
    cur, investigation_id: str, tenant_id: str, source_ip: str,
) -> Optional[CorrelationMatch]:
    """Rule 1: Same source IP within 24h window, min 2 alerts."""
    if not source_ip:
        return None
    cur.execute("""
        SELECT id, task_type, created_at,
               (output->>'risk_score')::int as risk,
               output->'mitre_techniques' as mitre
        FROM agent_tasks
        WHERE tenant_id = %s AND status = 'completed'
          AND input->'siem_event'->>'source_ip' = %s
          AND created_at > NOW() - INTERVAL '24 hours'
          AND id != %s::uuid
        ORDER BY created_at
    """, (tenant_id, source_ip, investigation_id))
    rows = cur.fetchall()
    if not rows:
        return None

    inv_ids = [str(r[0]) for r in rows] + [investigation_id]
    time_span = (rows[-1][2] - rows[0][2]).total_seconds() / 3600 if len(rows) > 1 else 0
    confidence = min(1.0, 0.5 + len(rows) * 0.1)

    return CorrelationMatch(
        rule="same_source_ip",
        investigations=inv_ids,
        confidence=confidence,
        chain_type="lateral_movement",
        time_span_hours=time_span,
        first_seen=rows[0][2],
        last_seen=rows[-1][2],
    )


def _rule_same_target_user(
    cur, investigation_id: str, tenant_id: str, username: str,
) -> Optional[CorrelationMatch]:
    """Rule 2: Same target user across alert types within 48h."""
    if not username:
        return None
    cur.execute("""
        SELECT id, task_type, created_at,
               (output->>'risk_score')::int as risk
        FROM agent_tasks
        WHERE tenant_id = %s AND status = 'completed'
          AND input->'siem_event'->>'username' = %s
          AND created_at > NOW() - INTERVAL '48 hours'
          AND id != %s::uuid
        ORDER BY created_at
    """, (tenant_id, username, investigation_id))
    rows = cur.fetchall()
    if not rows:
        return None

    # Only correlate if there are multiple DIFFERENT task_types
    task_types = {r[1] for r in rows}
    if len(task_types) < 2:
        return None

    inv_ids = [str(r[0]) for r in rows] + [investigation_id]
    confidence = min(1.0, 0.4 + len(task_types) * 0.15)

    return CorrelationMatch(
        rule="same_target_user",
        investigations=inv_ids,
        confidence=confidence,
        chain_type="targeted_attack",
        time_span_hours=(rows[-1][2] - rows[0][2]).total_seconds() / 3600,
        first_seen=rows[0][2],
        last_seen=rows[-1][2],
    )


def _rule_same_host_escalation(
    cur, investigation_id: str, tenant_id: str, hostname: str,
) -> Optional[CorrelationMatch]:
    """Rule 3: Same host with escalating severity within 12h."""
    if not hostname:
        return None
    cur.execute("""
        SELECT id, task_type, created_at,
               (output->>'risk_score')::int as risk,
               input->>'severity' as severity
        FROM agent_tasks
        WHERE tenant_id = %s AND status = 'completed'
          AND input->'siem_event'->>'hostname' = %s
          AND created_at > NOW() - INTERVAL '12 hours'
        ORDER BY created_at
    """, (tenant_id, hostname))
    rows = cur.fetchall()
    if len(rows) < 3:
        return None

    # Check for escalating risk
    risks = [r[3] or 0 for r in rows]
    escalating = all(risks[i] <= risks[i+1] for i in range(len(risks)-1))
    if not escalating:
        return None

    inv_ids = [str(r[0]) for r in rows]
    confidence = min(1.0, 0.6 + (risks[-1] - risks[0]) / 200)

    return CorrelationMatch(
        rule="same_host_escalation",
        investigations=inv_ids,
        confidence=confidence,
        chain_type="privilege_escalation",
        time_span_hours=(rows[-1][2] - rows[0][2]).total_seconds() / 3600,
        first_seen=rows[0][2],
        last_seen=rows[-1][2],
    )


def _rule_ioc_overlap(
    cur, investigation_id: str, tenant_id: str, iocs: list[str],
) -> Optional[CorrelationMatch]:
    """Rule 4: IOC overlap across investigations within 72h (min 2 shared)."""
    if len(iocs) < 2:
        return None
    # Search for other investigations sharing at least 2 IOCs
    cur.execute("""
        SELECT id, output->'iocs' as iocs_json, created_at
        FROM agent_tasks
        WHERE tenant_id = %s AND status = 'completed'
          AND id != %s::uuid
          AND created_at > NOW() - INTERVAL '72 hours'
          AND output->'iocs' IS NOT NULL
    """, (tenant_id, investigation_id))

    matches = []
    for row in cur.fetchall():
        try:
            other_iocs_raw = row[1]
            if isinstance(other_iocs_raw, str):
                other_iocs_raw = json.loads(other_iocs_raw)
            other_values = {
                i.get("value", "") for i in other_iocs_raw
                if isinstance(i, dict)
            }
            shared = set(iocs) & other_values
            if len(shared) >= 2:
                matches.append((str(row[0]), len(shared), row[2]))
        except (json.JSONDecodeError, TypeError):
            continue

    if not matches:
        return None

    inv_ids = [m[0] for m in matches] + [investigation_id]
    max_shared = max(m[1] for m in matches)
    confidence = min(1.0, 0.5 + max_shared * 0.1)

    return CorrelationMatch(
        rule="ioc_overlap",
        investigations=inv_ids,
        confidence=confidence,
        chain_type="campaign",
        time_span_hours=(
            max(m[2] for m in matches) - min(m[2] for m in matches)
        ).total_seconds() / 3600 if len(matches) > 1 else 0,
    )


def _rule_mitre_kill_chain(
    cur, investigation_id: str, tenant_id: str, mitre_techniques: list[str],
) -> Optional[CorrelationMatch]:
    """Rule 5: MITRE ATT&CK kill chain phase progression within 168h."""
    if not mitre_techniques:
        return None

    # Get phases for current investigation
    current_phases = set()
    for t in mitre_techniques:
        phase = _get_technique_phase(t)
        if phase:
            current_phases.add(phase)
    if not current_phases:
        return None

    # Find other investigations with MITRE techniques in complementary phases
    cur.execute("""
        SELECT id, output->'mitre_techniques' as mitre, created_at,
               (output->>'risk_score')::int as risk
        FROM agent_tasks
        WHERE tenant_id = %s AND status = 'completed'
          AND id != %s::uuid
          AND created_at > NOW() - INTERVAL '168 hours'
          AND output->'mitre_techniques' IS NOT NULL
    """, (tenant_id, investigation_id))

    all_phases_with_inv = []
    for row in cur.fetchall():
        try:
            techniques = row[1]
            if isinstance(techniques, str):
                techniques = json.loads(techniques)
            if not isinstance(techniques, list):
                continue
            for t in techniques:
                tid = t.get("id", t) if isinstance(t, dict) else str(t)
                phase = _get_technique_phase(tid)
                if phase:
                    all_phases_with_inv.append((phase, str(row[0]), row[2]))
        except (json.JSONDecodeError, TypeError):
            continue

    if not all_phases_with_inv:
        return None

    # Check for phase progression (at least 2 different phases)
    other_phases = {p[0] for p in all_phases_with_inv}
    combined = current_phases | other_phases
    if len(combined) < 3:
        return None

    # Check ordering against kill chain
    phase_indices = [KILL_CHAIN_ORDER.index(p) for p in combined if p in KILL_CHAIN_ORDER]
    if len(phase_indices) < 3:
        return None

    sorted_indices = sorted(phase_indices)
    span = sorted_indices[-1] - sorted_indices[0]

    inv_ids = list({p[1] for p in all_phases_with_inv}) + [investigation_id]
    mitre_chain = sorted(
        [t for t in mitre_techniques] +
        [t.get("id", t) if isinstance(t, dict) else str(t)
         for row_mitre in [p for p in all_phases_with_inv]
         for t in ([row_mitre[0]] if isinstance(row_mitre[0], str) else [])],
        key=lambda x: KILL_CHAIN_ORDER.index(_get_technique_phase(x) or "impact")
        if _get_technique_phase(x) else 99,
    )

    confidence = min(1.0, 0.3 + span * 0.1 + len(combined) * 0.05)

    return CorrelationMatch(
        rule="mitre_kill_chain",
        investigations=inv_ids,
        confidence=confidence,
        chain_type="kill_chain",
        mitre_chain=mitre_chain,
    )


# ── Main correlator ───────────────────────────────────────

def correlate_investigation(investigation_id: str, tenant_id: str) -> list[dict]:
    """Run all 5 correlation rules for a completed investigation.

    Returns list of attack paths created/updated.
    """
    conn = _get_db()
    paths_created = []

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Load the investigation
            cur.execute("""
                SELECT id, task_type, input, output, created_at
                FROM agent_tasks
                WHERE id = %s::uuid AND tenant_id = %s
            """, (investigation_id, tenant_id))
            inv = cur.fetchone()
            if not inv:
                logger.warning("Investigation %s not found", investigation_id)
                return []

            # Skip benign investigations
            verdict = (inv["output"] or {}).get("verdict", "")
            if verdict == "benign":
                return []

            # Extract correlation fields from SIEM event
            siem = (inv["input"] or {}).get("siem_event", {})
            source_ip = siem.get("source_ip", "")
            username = siem.get("username", "")
            hostname = siem.get("hostname", "")

            ioc_values = []
            iocs_raw = (inv["output"] or {}).get("iocs", [])
            if isinstance(iocs_raw, list):
                for ioc in iocs_raw:
                    if isinstance(ioc, dict) and ioc.get("value"):
                        ioc_values.append(ioc["value"])

            mitre_techniques = []
            mitre_raw = (inv["output"] or {}).get("mitre_techniques", [])
            if isinstance(mitre_raw, list):
                for t in mitre_raw:
                    if isinstance(t, dict):
                        mitre_techniques.append(t.get("id", ""))
                    elif isinstance(t, str):
                        mitre_techniques.append(t)

            # Run all correlation rules
            rules = [
                lambda: _rule_same_source_ip(cur, investigation_id, tenant_id, source_ip),
                lambda: _rule_same_target_user(cur, investigation_id, tenant_id, username),
                lambda: _rule_same_host_escalation(cur, investigation_id, tenant_id, hostname),
                lambda: _rule_ioc_overlap(cur, investigation_id, tenant_id, ioc_values),
                lambda: _rule_mitre_kill_chain(cur, investigation_id, tenant_id, mitre_techniques),
            ]

            for rule_fn in rules:
                try:
                    match = rule_fn()
                    if match and match.confidence >= MIN_CONFIDENCE:
                        path = _store_attack_path(cur, match, tenant_id)
                        if path:
                            paths_created.append(path)
                except Exception as e:
                    logger.warning("Correlation rule failed: %s", e)

        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Attack path correlation failed: %s", e)
        _store_dlq(investigation_id, tenant_id, str(e))
    finally:
        conn.close()

    return paths_created


def _store_attack_path(
    cur, match: CorrelationMatch, tenant_id: str,
) -> Optional[dict]:
    """Insert or update an attack path from a correlation match."""
    # Generate deterministic path_id from sorted investigation IDs
    sorted_inv = sorted(set(match.investigations))
    path_id = f"ap-{match.rule}-" + hashlib.md5(
        "|".join(sorted_inv).encode()
    ).hexdigest()[:12]

    # Check if path already exists
    cur.execute(
        "SELECT id, investigations FROM attack_paths "
        "WHERE path_id = %s AND tenant_id = %s",
        (path_id, tenant_id),
    )
    existing = cur.fetchone()

    composite_risk = 0
    for inv_id in sorted_inv:
        cur.execute(
            "SELECT (output->>'risk_score')::int FROM agent_tasks WHERE id = %s::uuid",
            (inv_id,),
        )
        row = cur.fetchone()
        if row and row[0]:
            composite_risk = max(composite_risk, row[0])

    if existing:
        # Update existing path
        cur.execute("""
            UPDATE attack_paths SET
                investigations = %s,
                composite_risk = %s,
                confidence = %s,
                last_seen = NOW(),
                updated_at = NOW()
            WHERE id = %s
        """, (sorted_inv, composite_risk, match.confidence, existing[0]))
        return {"path_id": path_id, "action": "updated"}
    else:
        cur.execute("""
            INSERT INTO attack_paths
                (path_id, chain_type, confidence, investigations,
                 mitre_chain, composite_risk, time_span_hours,
                 first_seen, last_seen, correlation_rule, tenant_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            path_id, match.chain_type, match.confidence,
            sorted_inv, match.mitre_chain or [],
            composite_risk, match.time_span_hours,
            match.first_seen, match.last_seen,
            match.rule, tenant_id,
        ))
        return {"path_id": path_id, "action": "created"}


def _store_dlq(
    investigation_id: str, tenant_id: str, error_message: str,
    error_type: str = "correlation_error",
) -> None:
    """Store failed correlation in dead letter queue."""
    try:
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO attack_path_dlq
                        (investigation_id, error_message, error_type, tenant_id)
                    VALUES (%s::uuid, %s, %s, %s)
                """, (investigation_id, error_message, error_type, tenant_id))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.error("Failed to store DLQ entry: %s", e)


# Need hashlib for path_id generation
import hashlib
