"""
Contextual Risk Scoring — adjusts base risk using asset criticality.

Called by assess.py AFTER base verdict derivation.
Unknown assets (not in registry) get NO adjustment.

Conservative multipliers:
  Criticality: 0.8x–1.2x
  Exposure:    0.9x–1.2x
  Privilege:   1.0x–1.3x
  Combined range: 0.72x–1.87x

Output stores both risk_score_base and risk_score (adjusted)
plus context_adjustment factors for audit trail.
"""
import logging
import os
from dataclasses import dataclass
from typing import Optional

import psycopg2

logger = logging.getLogger(__name__)

# ── Multiplier tables (conservative per PRD) ──────────────

CRITICALITY_MULT = {
    # Linear interpolation: crit=0 → 0.8x, crit=100 → 1.2x
}

EXPOSURE_MULT = {
    "external": 1.2,
    "dmz": 1.1,
    "internal": 1.0,
    "isolated": 0.9,
}

PRIVILEGE_MULT = {
    "system": 1.3,
    "admin": 1.2,
    "privileged": 1.15,
    "standard": 1.0,
    "service": 1.1,
}


@dataclass
class Asset:
    identifier: str
    identifier_type: str
    criticality: int
    exposure: str
    privilege_level: str


@dataclass
class ContextAdjustment:
    risk_score_base: int
    risk_score: int
    asset_identifier: Optional[str]
    criticality_mult: float
    exposure_mult: float
    privilege_mult: float
    combined_mult: float


def _get_db():
    from settings import settings as _s
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", _s.database_url)
    )


def _criticality_multiplier(criticality: int) -> float:
    """Linear interpolation: 0 → 0.8, 50 → 1.0, 100 → 1.2."""
    return 0.8 + (criticality / 100) * 0.4


def lookup_asset(
    identifier: str, identifier_type: str, tenant_id: str,
) -> Optional[Asset]:
    """Look up an asset in the registry. Returns None if not found."""
    try:
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT identifier, identifier_type, criticality, "
                    "exposure, privilege_level FROM asset_registry "
                    "WHERE identifier = %s AND identifier_type = %s "
                    "AND tenant_id = %s",
                    (identifier, identifier_type, tenant_id),
                )
                row = cur.fetchone()
                if row:
                    return Asset(
                        identifier=row[0],
                        identifier_type=row[1],
                        criticality=row[2],
                        exposure=row[3],
                        privilege_level=row[4],
                    )
        finally:
            conn.close()
    except Exception as e:
        logger.debug("Asset lookup failed: %s", e)
    return None


def contextual_risk(
    base_risk: int, tenant_id: str,
    source_ip: str = "", hostname: str = "",
    username: str = "",
) -> ContextAdjustment:
    """Adjust base risk score using asset context.

    Looks up source_ip, hostname, and username in asset_registry.
    Uses the highest-criticality match for adjustment.
    Unknown assets get no adjustment (multiplier = 1.0).

    Returns ContextAdjustment with both base and adjusted scores.
    """
    identifiers = []
    if source_ip:
        identifiers.append((source_ip, "ip"))
    if hostname:
        identifiers.append((hostname, "host"))
    if username:
        identifiers.append((username, "user"))

    # Find the most critical matching asset
    best_asset: Optional[Asset] = None
    for ident, ident_type in identifiers:
        asset = lookup_asset(ident, ident_type, tenant_id)
        if asset:
            if best_asset is None or asset.criticality > best_asset.criticality:
                best_asset = asset

    if best_asset is None:
        return ContextAdjustment(
            risk_score_base=base_risk,
            risk_score=base_risk,
            asset_identifier=None,
            criticality_mult=1.0,
            exposure_mult=1.0,
            privilege_mult=1.0,
            combined_mult=1.0,
        )

    crit_m = _criticality_multiplier(best_asset.criticality)
    expo_m = EXPOSURE_MULT.get(best_asset.exposure, 1.0)
    priv_m = PRIVILEGE_MULT.get(best_asset.privilege_level, 1.0)
    combined = crit_m * expo_m * priv_m

    adjusted = min(100, max(0, int(base_risk * combined)))

    return ContextAdjustment(
        risk_score_base=base_risk,
        risk_score=adjusted,
        asset_identifier=best_asset.identifier,
        criticality_mult=round(crit_m, 3),
        exposure_mult=round(expo_m, 3),
        privilege_mult=round(priv_m, 3),
        combined_mult=round(combined, 3),
    )


def record_asset_occurrence(
    tenant_id: str, identifier: str, identifier_type: str,
    attack_type: str = "",
) -> None:
    """Record that an asset appeared in an investigation.

    Used for auto-discovery: assets appearing in 5+ investigations
    get suggested for the registry.
    """
    try:
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO asset_occurrences
                        (identifier, identifier_type, occurrence_count,
                         attack_types, tenant_id)
                    VALUES (%s, %s, 1, ARRAY[%s]::text[], %s)
                    ON CONFLICT (identifier, identifier_type, tenant_id, created_at)
                    DO UPDATE SET
                        occurrence_count = asset_occurrences.occurrence_count + 1,
                        last_seen = NOW(),
                        attack_types = array_append(
                            asset_occurrences.attack_types, %s
                        )
                """, (identifier, identifier_type, attack_type,
                      tenant_id, attack_type))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.debug("Asset occurrence record failed: %s", e)
