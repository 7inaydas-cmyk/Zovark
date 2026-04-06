"""
Pydantic models for .zvk bundle format.

Verification order:
1. os.stat() — reject if > 10 MB (no parsing)
2. Ed25519 signature verification on raw bytes
3. JSON parse + Pydantic schema validation
4. Size limit checks on individual fields
5. Sequence number / expiry / revocation checks

Bundle files are Ed25519-signed JSON with the structure:
{
  "signature": "<hex Ed25519 signature of contents_json>",
  "contents_json": "<JSON string of BundleContents>"
}
"""
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ── Size limits ──────────────────────────────────────────
MAX_BUNDLE_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_DETECTION_TOOL_SIZE = 100 * 1024     # 100 KB
MAX_INVESTIGATION_PLAN_SIZE = 50 * 1024  # 50 KB
MAX_SKILL_TEMPLATE_SIZE = 200 * 1024     # 200 KB
MAX_ANCHORS_PER_TYPE = 10


# ── Content item models ──────────────────────────────────

class InvestigationPlanItem(BaseModel):
    """A single investigation plan delivered via bundle."""
    plan_key: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=20, pattern=r"^\d+\.\d+\.\d+$")
    tier: str = Field(default="community", pattern=r"^(community|premium)$")
    plan_data: dict
    replaces: Optional[str] = None

    @field_validator("plan_data")
    @classmethod
    def validate_plan_data_size(cls, v):
        raw = json.dumps(v)
        if len(raw.encode()) > MAX_INVESTIGATION_PLAN_SIZE:
            raise ValueError(
                f"Plan data exceeds {MAX_INVESTIGATION_PLAN_SIZE // 1024} KB limit"
            )
        return v


class SkillTemplateItem(BaseModel):
    """A skill template (agent_skills entry) delivered via bundle."""
    slug: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=20, pattern=r"^\d+\.\d+\.\d+$")
    tier: str = Field(default="community", pattern=r"^(community|premium)$")
    task_types: list[str] = Field(default_factory=list)
    code_template: str
    description: str = ""

    @field_validator("code_template")
    @classmethod
    def validate_template_size(cls, v):
        if len(v.encode()) > MAX_SKILL_TEMPLATE_SIZE:
            raise ValueError(
                f"Template exceeds {MAX_SKILL_TEMPLATE_SIZE // 1024} KB limit"
            )
        return v


class DetectionToolItem(BaseModel):
    """A detection tool function delivered via bundle."""
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=20, pattern=r"^\d+\.\d+\.\d+$")
    tier: str = Field(default="community", pattern=r"^(community|premium)$")
    function_code: str
    risk_weights: Optional[dict] = None
    test_cases: list[dict] = Field(default_factory=list)

    @field_validator("function_code")
    @classmethod
    def validate_tool_size(cls, v):
        if len(v.encode()) > MAX_DETECTION_TOOL_SIZE:
            raise ValueError(
                f"Tool code exceeds {MAX_DETECTION_TOOL_SIZE // 1024} KB limit"
            )
        return v


class ToolSubsetUpdate(BaseModel):
    """Updates to tool_subsets.py attack-type-to-tools mapping."""
    attack_type: str = Field(min_length=1, max_length=100)
    tools: list[str]


class MitreMappingItem(BaseModel):
    """A MITRE ATT&CK technique mapping."""
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    tactic: str
    technique_name: str


class RiskCalibrationAnchor(BaseModel):
    """Risk calibration anchor for assess.py prompt."""
    attack_type: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=500)
    risk: int = Field(ge=0, le=100)


class DeletionItem(BaseModel):
    """Explicit content removal."""
    content_type: str = Field(
        pattern=r"^(detection_tool|investigation_plan|skill_template)$"
    )
    name: str = Field(min_length=1, max_length=100)


class BundleContents(BaseModel):
    """All content types that can be delivered in a bundle."""
    investigation_plans: list[InvestigationPlanItem] = Field(default_factory=list)
    skill_templates: list[SkillTemplateItem] = Field(default_factory=list)
    detection_tools: list[DetectionToolItem] = Field(default_factory=list)
    tool_subset_updates: list[ToolSubsetUpdate] = Field(default_factory=list)
    mitre_mappings: list[MitreMappingItem] = Field(default_factory=list)
    risk_calibration: list[RiskCalibrationAnchor] = Field(default_factory=list)
    deletions: list[DeletionItem] = Field(default_factory=list)

    @field_validator("risk_calibration")
    @classmethod
    def validate_anchor_limits(cls, v):
        counts: dict[str, int] = {}
        for anchor in v:
            counts[anchor.attack_type] = counts.get(anchor.attack_type, 0) + 1
            if counts[anchor.attack_type] > MAX_ANCHORS_PER_TYPE:
                raise ValueError(
                    f"Too many anchors for {anchor.attack_type}: "
                    f"max {MAX_ANCHORS_PER_TYPE}"
                )
        return v


class BundleManifest(BaseModel):
    """Top-level bundle metadata."""
    bundle_id: str = Field(min_length=1, max_length=100)
    sequence_number: int = Field(ge=0)
    version: str = Field(min_length=1, max_length=20, pattern=r"^\d+\.\d+\.\d+$")
    tier: str = Field(default="community", pattern=r"^(community|premium)$")
    created_at: str  # ISO 8601
    changelog: str = ""
    expires_at: Optional[str] = None  # ISO 8601
    contents: BundleContents


class SignedBundle(BaseModel):
    """Wire format: signature + JSON payload."""
    signature: str = Field(min_length=128, max_length=128)  # Ed25519 hex = 128 chars
    contents_json: str


# ── Verification functions ────────────────────────────────

def verify_bundle_file_size(path: str) -> None:
    """Step 1: Reject bundles larger than 10 MB without parsing."""
    size = os.stat(path).st_size
    if size > MAX_BUNDLE_FILE_SIZE:
        raise ValueError(
            f"Bundle file too large: {size} bytes "
            f"(max {MAX_BUNDLE_FILE_SIZE // (1024*1024)} MB)"
        )


def verify_bundle_signature(
    contents_json: str,
    signature_hex: str,
    public_key_bytes: bytes,
) -> bool:
    """Step 2: Verify Ed25519 signature on raw contents_json bytes.

    Returns True if valid, raises ValueError if invalid.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        sig_bytes = bytes.fromhex(signature_hex)
        pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(sig_bytes, contents_json.encode("utf-8"))
        return True
    except Exception as exc:
        raise ValueError(f"Invalid bundle signature: {exc}") from exc


def parse_and_validate_bundle(contents_json: str) -> BundleManifest:
    """Steps 3-4: Parse JSON and validate with Pydantic (includes size checks)."""
    data = json.loads(contents_json)
    return BundleManifest.model_validate(data)


def check_sequence_and_expiry(
    manifest: BundleManifest,
    last_installed_sequence: int,
    revoked_ids: set[str],
) -> None:
    """Step 5: Anti-replay, expiry, and revocation checks."""
    # Anti-replay: sequence must be strictly monotonic
    if manifest.sequence_number <= last_installed_sequence:
        raise ValueError(
            f"Bundle sequence {manifest.sequence_number} <= "
            f"last installed {last_installed_sequence} (anti-replay)"
        )

    # Expiry check
    if manifest.expires_at:
        try:
            expires = datetime.fromisoformat(manifest.expires_at)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires < datetime.now(timezone.utc):
                raise ValueError(
                    f"Bundle expired at {manifest.expires_at}"
                )
        except (ValueError, TypeError):
            pass  # Malformed expiry treated as non-expiring

    # Revocation check
    if manifest.bundle_id in revoked_ids:
        raise ValueError(
            f"Bundle {manifest.bundle_id} has been revoked"
        )


def load_and_verify_bundle(
    path: str,
    public_key_bytes: bytes,
    last_installed_sequence: int,
    revoked_ids: set[str],
) -> BundleManifest:
    """Full verification pipeline: size → sig → parse → seq/expiry.

    Returns validated BundleManifest on success.
    Raises ValueError on any failure.
    """
    # Step 1: File size
    verify_bundle_file_size(path)

    # Step 2: Load and verify signature
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    signed = SignedBundle.model_validate_json(raw)
    verify_bundle_signature(
        signed.contents_json,
        signed.signature,
        public_key_bytes,
    )

    # Steps 3-4: Parse and validate contents
    manifest = parse_and_validate_bundle(signed.contents_json)

    # Step 5: Sequence, expiry, revocation
    check_sequence_and_expiry(
        manifest, last_installed_sequence, revoked_ids
    )

    logger.info(
        "Bundle verified: id=%s seq=%d version=%s items=%d",
        manifest.bundle_id,
        manifest.sequence_number,
        manifest.version,
        sum([
            len(manifest.contents.investigation_plans),
            len(manifest.contents.skill_templates),
            len(manifest.contents.detection_tools),
            len(manifest.contents.tool_subset_updates),
            len(manifest.contents.mitre_mappings),
            len(manifest.contents.risk_calibration),
            len(manifest.contents.deletions),
        ]),
    )
    return manifest


# ── Diff/preview ──────────────────────────────────────────

def bundle_diff(manifest: BundleManifest, existing: dict) -> list[str]:
    """Generate human-readable diff of what a bundle would change.

    Args:
        manifest: Validated bundle manifest.
        existing: Dict of {content_type: {name: version}} from DB.

    Returns:
        List of diff lines for operator review.
    """
    lines: list[str] = []
    lines.append(f"Bundle: {manifest.bundle_id} v{manifest.version} "
                 f"(seq {manifest.sequence_number}, tier={manifest.tier})")
    if manifest.changelog:
        lines.append(f"Changelog: {manifest.changelog}")
    lines.append("")

    # Plans
    for plan in manifest.contents.investigation_plans:
        ex = existing.get("plans", {}).get(plan.plan_key)
        if ex:
            lines.append(f"  [MODIFY] plan/{plan.plan_key}: {ex} → {plan.version}")
        else:
            lines.append(f"  [NEW]    plan/{plan.plan_key}: {plan.version}")
        if plan.replaces:
            ref_exists = plan.replaces in existing.get("plans", {})
            if not ref_exists:
                lines.append(
                    f"  ⚠ WARNING: replaces '{plan.replaces}' not found in DB"
                )

    # Templates
    for tmpl in manifest.contents.skill_templates:
        ex = existing.get("templates", {}).get(tmpl.slug)
        if ex:
            lines.append(f"  [MODIFY] template/{tmpl.slug}: {ex} → {tmpl.version}")
        else:
            lines.append(f"  [NEW]    template/{tmpl.slug}: {tmpl.version}")

    # Detection tools
    for tool in manifest.contents.detection_tools:
        ex = existing.get("tools", {}).get(tool.name)
        if ex:
            lines.append(f"  [MODIFY] tool/{tool.name}: {ex} → {tool.version}")
        else:
            lines.append(f"  [NEW]    tool/{tool.name}: {tool.version}")
        lines.append(f"           source: {len(tool.function_code)} bytes, "
                     f"{len(tool.test_cases)} test cases")

    # Calibration
    for anchor in manifest.contents.risk_calibration:
        lines.append(
            f"  [ANCHOR] {anchor.attack_type}: "
            f"risk={anchor.risk} — {anchor.description[:60]}"
        )

    # MITRE mappings
    for m in manifest.contents.mitre_mappings:
        lines.append(f"  [MITRE]  {m.technique_id}: {m.technique_name}")

    # Deletions
    for d in manifest.contents.deletions:
        lines.append(f"  [DELETE] {d.content_type}/{d.name}")

    if not any(x for x in lines if x.startswith("  [")):
        lines.append("  (empty bundle — no content changes)")

    return lines
