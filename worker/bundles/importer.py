"""
Bundle importer — atomic apply or full rollback.

Imports verified bundle contents into the database:
- Investigation plans → investigation_plans_db
- Skill templates → agent_skills + agent_skills_metadata
- Detection tools → bundle_detection_tools (staged inactive until DAST)
- Risk calibration → risk_calibration_anchors
- MITRE mappings → mitre_mapping.py runtime update
- Deletions → soft-delete (active=false)

Conflict resolution: higher semver wins.
Same version: higher sequence_number wins.

Plan generation pinning: in-flight investigations keep their
generation's plans. New plans take effect after next analyze.py load.
"""
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras

from worker.bundles.bundle_schema import BundleManifest
from worker.bundles.security import run_sast, run_dast

logger = logging.getLogger(__name__)

# Plan generation counter for in-flight pinning
_plan_generation = 0
_plans_cache: dict[int, dict] = {}
_plans_cache_time: float = 0.0
PLAN_CACHE_TTL = 300  # 5 minutes


def _get_db():
    from worker.settings import settings as _settings
    url = os.environ.get("DATABASE_URL", _settings.database_url)
    return psycopg2.connect(url)


def _semver_tuple(v: str) -> tuple[int, ...]:
    """Parse "1.2.3" into (1, 2, 3) for comparison."""
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _semver_gte(a: str, b: str) -> bool:
    """True if version a >= version b."""
    return _semver_tuple(a) >= _semver_tuple(b)


# ── Plan generation pinning ───────────────────────────────

def invalidate_plan_cache():
    """Bump generation counter after bundle import.

    In-flight investigations retain their generation.
    """
    global _plan_generation, _plans_cache_time
    _plan_generation += 1
    _plans_cache_time = 0.0  # Force reload
    logger.info("Plan cache invalidated, generation=%d", _plan_generation)


def get_current_generation() -> int:
    """Return current plan generation for new investigations."""
    return _plan_generation


def get_plans_for_generation(generation: Optional[int] = None) -> dict:
    """Load plans from DB + file, cached per generation.

    DB plans take priority over file plans for same plan_key.
    """
    import time

    gen = generation if generation is not None else _plan_generation
    now = time.time()

    # Return cached if fresh
    if gen in _plans_cache and (now - _plans_cache_time) < PLAN_CACHE_TTL:
        return _plans_cache[gen]

    # Load file-based plans (investigation_plans.json)
    plans = {}
    try:
        plans_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "tools", "investigation_plans.json",
        )
        with open(plans_path) as f:
            plans = json.load(f)
    except Exception as e:
        logger.warning("Could not load file plans: %s", e)

    # Load DB plans (override file for same key)
    try:
        conn = _get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT plan_key, plan_data FROM investigation_plans_db "
                    "WHERE active = true"
                )
                for row in cur.fetchall():
                    plans[row["plan_key"]] = row["plan_data"]
        finally:
            conn.close()
    except Exception as e:
        logger.warning("Could not load DB plans: %s", e)

    _plans_cache[gen] = plans
    global _plans_cache_time
    _plans_cache_time = now

    # Keep at most 3 generations cached
    if len(_plans_cache) > 3:
        oldest = min(_plans_cache.keys())
        del _plans_cache[oldest]

    return plans


# ── Import functions ──────────────────────────────────────

def _import_plans(conn, manifest: BundleManifest) -> list[str]:
    """Import investigation plans. Returns list of actions taken."""
    actions = []
    with conn.cursor() as cur:
        for plan in manifest.contents.investigation_plans:
            # Check existing
            cur.execute(
                "SELECT version FROM investigation_plans_db "
                "WHERE plan_key = %s AND active = true",
                (plan.plan_key,),
            )
            row = cur.fetchone()
            if row and _semver_gte(row[0], plan.version):
                actions.append(f"SKIP plan/{plan.plan_key}: "
                               f"existing {row[0]} >= {plan.version}")
                continue

            # Deactivate old version
            cur.execute(
                "UPDATE investigation_plans_db SET active = false, "
                "updated_at = NOW() WHERE plan_key = %s AND active = true",
                (plan.plan_key,),
            )

            # Insert new version
            cur.execute(
                "INSERT INTO investigation_plans_db "
                "(plan_key, tier, version, bundle_id, bundle_sequence, "
                "plan_data, active, replaces) "
                "VALUES (%s, %s, %s, %s, %s, %s, true, %s)",
                (plan.plan_key, plan.tier, plan.version,
                 manifest.bundle_id, manifest.sequence_number,
                 json.dumps(plan.plan_data), plan.replaces),
            )
            actions.append(f"IMPORT plan/{plan.plan_key} v{plan.version}")
    return actions


def _import_templates(conn, manifest: BundleManifest) -> list[str]:
    """Import skill templates into agent_skills + metadata."""
    actions = []
    with conn.cursor() as cur:
        for tmpl in manifest.contents.skill_templates:
            # Check existing by slug
            cur.execute(
                "SELECT id, version FROM agent_skills_metadata asm "
                "JOIN agent_skills a ON a.id = asm.skill_id "
                "WHERE a.slug = %s",
                (tmpl.slug,),
            )
            row = cur.fetchone()
            if row and row[1] and _semver_gte(row[1], tmpl.version):
                actions.append(f"SKIP template/{tmpl.slug}: "
                               f"existing {row[1]} >= {tmpl.version}")
                continue

            if row:
                # Update existing
                skill_id = row[0]
                cur.execute(
                    "UPDATE agent_skills SET code_template = %s, "
                    "description = %s WHERE id = %s",
                    (tmpl.code_template, tmpl.description, skill_id),
                )
                cur.execute(
                    "UPDATE agent_skills_metadata SET "
                    "tier = %s, bundle_id = %s, bundle_version = %s "
                    "WHERE skill_id = %s",
                    (tmpl.tier, manifest.bundle_id, tmpl.version, skill_id),
                )
                actions.append(f"UPDATE template/{tmpl.slug} v{tmpl.version}")
            else:
                # Insert new skill
                cur.execute(
                    "INSERT INTO agent_skills "
                    "(slug, description, code_template, task_types) "
                    "VALUES (%s, %s, %s, %s) RETURNING id",
                    (tmpl.slug, tmpl.description, tmpl.code_template,
                     tmpl.task_types),
                )
                skill_id = cur.fetchone()[0]
                cur.execute(
                    "INSERT INTO agent_skills_metadata "
                    "(skill_id, tier, bundle_id, bundle_version) "
                    "VALUES (%s, %s, %s, %s)",
                    (skill_id, tmpl.tier, manifest.bundle_id, tmpl.version),
                )
                actions.append(f"IMPORT template/{tmpl.slug} v{tmpl.version}")
    return actions


def _import_detection_tools(
    conn, manifest: BundleManifest, skip_runtime: bool = False,
) -> list[str]:
    """Import detection tools with SAST. Tools staged inactive until DAST passes."""
    actions = []
    with conn.cursor() as cur:
        for tool in manifest.contents.detection_tools:
            # Check existing
            cur.execute(
                "SELECT version FROM bundle_detection_tools "
                "WHERE name = %s AND active = true",
                (tool.name,),
            )
            row = cur.fetchone()
            if row and _semver_gte(row[0], tool.version):
                actions.append(f"SKIP tool/{tool.name}: "
                               f"existing {row[0]} >= {tool.version}")
                continue

            # Run SAST
            sast_result = run_sast(tool.function_code, skip_runtime=skip_runtime)
            sast_report = sast_result.report

            if not sast_result.safe:
                actions.append(
                    f"REJECT tool/{tool.name} v{tool.version}: "
                    f"SAST failed ({len(sast_result.issues)} issues)"
                )
                # Still insert as inactive for operator review
                cur.execute(
                    "INSERT INTO bundle_detection_tools "
                    "(name, version, tier, bundle_id, bundle_sequence, "
                    "function_code, risk_weights, test_cases, "
                    "sast_passed, sast_report, active) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, false, %s, false) "
                    "ON CONFLICT (name, version) DO NOTHING",
                    (tool.name, tool.version, tool.tier,
                     manifest.bundle_id, manifest.sequence_number,
                     tool.function_code,
                     json.dumps(tool.risk_weights) if tool.risk_weights else None,
                     json.dumps(tool.test_cases) if tool.test_cases else None,
                     json.dumps(sast_report)),
                )
                continue

            # SAST passed — run DAST if test cases exist
            dast_passed = True
            if tool.test_cases:
                dast_passed, dast_results = run_dast(
                    tool.function_code, tool.test_cases,
                )
                sast_report["dast_results"] = dast_results

            # Deactivate old version
            cur.execute(
                "UPDATE bundle_detection_tools SET active = false "
                "WHERE name = %s AND active = true",
                (tool.name,),
            )

            # Insert — active only if DAST passed
            is_active = sast_result.safe and dast_passed
            cur.execute(
                "INSERT INTO bundle_detection_tools "
                "(name, version, tier, bundle_id, bundle_sequence, "
                "function_code, risk_weights, test_cases, "
                "sast_passed, sast_report, active) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (name, version) DO NOTHING",
                (tool.name, tool.version, tool.tier,
                 manifest.bundle_id, manifest.sequence_number,
                 tool.function_code,
                 json.dumps(tool.risk_weights) if tool.risk_weights else None,
                 json.dumps(tool.test_cases) if tool.test_cases else None,
                 sast_result.safe, json.dumps(sast_report), is_active),
            )

            status = "IMPORT" if is_active else "STAGED"
            actions.append(
                f"{status} tool/{tool.name} v{tool.version} "
                f"(SAST=pass, DAST={'pass' if dast_passed else 'FAIL'})"
            )
    return actions


def _import_calibration(conn, manifest: BundleManifest) -> list[str]:
    """Import risk calibration anchors."""
    actions = []
    with conn.cursor() as cur:
        for anchor in manifest.contents.risk_calibration:
            cur.execute(
                "INSERT INTO risk_calibration_anchors "
                "(attack_type, description, risk, bundle_id, bundle_sequence) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (attack_type, description) DO UPDATE SET "
                "risk = EXCLUDED.risk, bundle_id = EXCLUDED.bundle_id, "
                "bundle_sequence = EXCLUDED.bundle_sequence",
                (anchor.attack_type, anchor.description, anchor.risk,
                 manifest.bundle_id, manifest.sequence_number),
            )
            actions.append(
                f"ANCHOR {anchor.attack_type}: risk={anchor.risk}"
            )
    return actions


def _apply_deletions(conn, manifest: BundleManifest) -> list[str]:
    """Soft-delete content referenced in deletions array."""
    actions = []
    with conn.cursor() as cur:
        for d in manifest.contents.deletions:
            if d.content_type == "detection_tool":
                cur.execute(
                    "UPDATE bundle_detection_tools SET active = false "
                    "WHERE name = %s AND active = true",
                    (d.name,),
                )
            elif d.content_type == "investigation_plan":
                cur.execute(
                    "UPDATE investigation_plans_db SET active = false, "
                    "updated_at = NOW() WHERE plan_key = %s AND active = true",
                    (d.name,),
                )
            elif d.content_type == "skill_template":
                cur.execute(
                    "UPDATE agent_skills SET is_active = false "
                    "WHERE slug = %s",
                    (d.name,),
                )
            actions.append(f"DELETE {d.content_type}/{d.name}")
    return actions


def _build_rollback_snapshot(conn, manifest: BundleManifest) -> dict:
    """Capture current state of content that will be modified."""
    snapshot: dict = {"plans": {}, "tools": {}, "templates": {}}
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # Plans being replaced
        for plan in manifest.contents.investigation_plans:
            cur.execute(
                "SELECT plan_key, version, plan_data FROM investigation_plans_db "
                "WHERE plan_key = %s AND active = true",
                (plan.plan_key,),
            )
            row = cur.fetchone()
            if row:
                snapshot["plans"][row["plan_key"]] = {
                    "version": row["version"],
                    "plan_data": row["plan_data"],
                }

        # Tools being replaced
        for tool in manifest.contents.detection_tools:
            cur.execute(
                "SELECT name, version, function_code FROM bundle_detection_tools "
                "WHERE name = %s AND active = true",
                (tool.name,),
            )
            row = cur.fetchone()
            if row:
                snapshot["tools"][row["name"]] = {
                    "version": row["version"],
                }

    return snapshot


# ── Main entry points ─────────────────────────────────────

def import_bundle(
    manifest: BundleManifest,
    skip_runtime: bool = False,
    dry_run: bool = False,
) -> dict:
    """Import a verified bundle into the database.

    Atomic: all-or-nothing within a single transaction.
    Returns summary of actions taken.
    """
    conn = _get_db()
    all_actions: list[str] = []

    try:
        conn.autocommit = False

        # Build rollback snapshot before changes
        snapshot = _build_rollback_snapshot(conn, manifest)

        # Import each content type
        all_actions.extend(_import_plans(conn, manifest))
        all_actions.extend(_import_templates(conn, manifest))
        all_actions.extend(
            _import_detection_tools(conn, manifest, skip_runtime=skip_runtime)
        )
        all_actions.extend(_import_calibration(conn, manifest))
        all_actions.extend(_apply_deletions(conn, manifest))

        # Record the installed bundle
        with conn.cursor() as cur:
            contents_summary = {
                "plans": len(manifest.contents.investigation_plans),
                "templates": len(manifest.contents.skill_templates),
                "tools": len(manifest.contents.detection_tools),
                "calibration": len(manifest.contents.risk_calibration),
                "mitre": len(manifest.contents.mitre_mappings),
                "deletions": len(manifest.contents.deletions),
            }
            cur.execute(
                "INSERT INTO installed_bundles "
                "(bundle_id, sequence_number, tier, installed_by, "
                "changelog, contents_summary, rollback_snapshot, expires_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (bundle_id) DO UPDATE SET "
                "sequence_number = EXCLUDED.sequence_number, "
                "installed_at = NOW(), "
                "contents_summary = EXCLUDED.contents_summary, "
                "rollback_snapshot = EXCLUDED.rollback_snapshot",
                (manifest.bundle_id, manifest.sequence_number,
                 manifest.tier, "zvadmin",
                 manifest.changelog,
                 json.dumps(contents_summary),
                 json.dumps(snapshot),
                 manifest.expires_at),
            )

        if dry_run:
            conn.rollback()
            logger.info("Dry run — rolled back")
        else:
            conn.commit()
            invalidate_plan_cache()
            logger.info(
                "Bundle %s imported: %d actions",
                manifest.bundle_id, len(all_actions),
            )

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "bundle_id": manifest.bundle_id,
        "sequence_number": manifest.sequence_number,
        "actions": all_actions,
        "dry_run": dry_run,
    }


def rollback_bundle(bundle_id: str) -> dict:
    """Rollback a bundle: soft-delete its content, restore previous state."""
    conn = _get_db()
    actions: list[str] = []

    try:
        conn.autocommit = False

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Load snapshot
            cur.execute(
                "SELECT rollback_snapshot FROM installed_bundles "
                "WHERE bundle_id = %s AND rolled_back = false",
                (bundle_id,),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError(f"Bundle {bundle_id} not found or already rolled back")

            snapshot = row["rollback_snapshot"] or {}

            # Deactivate bundle content
            cur.execute(
                "UPDATE investigation_plans_db SET active = false, "
                "updated_at = NOW() WHERE bundle_id = %s",
                (bundle_id,),
            )
            cur.execute(
                "UPDATE bundle_detection_tools SET active = false "
                "WHERE bundle_id = %s",
                (bundle_id,),
            )
            actions.append(f"Deactivated all content from {bundle_id}")

            # Restore previous plans from snapshot
            for plan_key, prev in snapshot.get("plans", {}).items():
                cur.execute(
                    "UPDATE investigation_plans_db SET active = true, "
                    "updated_at = NOW() "
                    "WHERE plan_key = %s AND version = %s",
                    (plan_key, prev["version"]),
                )
                actions.append(f"Restored plan/{plan_key} v{prev['version']}")

            # Mark bundle as rolled back
            cur.execute(
                "UPDATE installed_bundles SET rolled_back = true "
                "WHERE bundle_id = %s",
                (bundle_id,),
            )

        conn.commit()
        invalidate_plan_cache()
        logger.info("Bundle %s rolled back: %d actions", bundle_id, len(actions))

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {"bundle_id": bundle_id, "actions": actions}
