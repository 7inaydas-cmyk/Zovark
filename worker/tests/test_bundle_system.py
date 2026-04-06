"""
Tests for the Zovark Bundle System (Sprint A).
Covers: schema validation, SAST security gates, importer logic.
"""
import json
import pytest


# ── Bundle Schema Tests ───────────────────────────────────

class TestBundleSchema:
    """Validate .zvk bundle format parsing and limits."""

    def test_valid_manifest(self):
        from worker.bundles.bundle_schema import BundleManifest

        data = {
            "bundle_id": "zvk-test-001",
            "sequence_number": 1,
            "version": "1.0.0",
            "tier": "community",
            "created_at": "2026-04-06T00:00:00Z",
            "changelog": "Test bundle",
            "contents": {
                "investigation_plans": [],
                "skill_templates": [],
                "detection_tools": [],
            },
        }
        m = BundleManifest.model_validate(data)
        assert m.bundle_id == "zvk-test-001"
        assert m.sequence_number == 1

    def test_invalid_version_format(self):
        from worker.bundles.bundle_schema import BundleManifest
        from pydantic import ValidationError

        data = {
            "bundle_id": "zvk-test-002",
            "sequence_number": 1,
            "version": "not-a-version",
            "tier": "community",
            "created_at": "2026-04-06T00:00:00Z",
            "contents": {},
        }
        with pytest.raises(ValidationError):
            BundleManifest.model_validate(data)

    def test_invalid_tier(self):
        from worker.bundles.bundle_schema import BundleManifest
        from pydantic import ValidationError

        data = {
            "bundle_id": "zvk-test-003",
            "sequence_number": 1,
            "version": "1.0.0",
            "tier": "enterprise",  # Not valid
            "created_at": "2026-04-06T00:00:00Z",
            "contents": {},
        }
        with pytest.raises(ValidationError):
            BundleManifest.model_validate(data)

    def test_detection_tool_size_limit(self):
        from worker.bundles.bundle_schema import DetectionToolItem
        from pydantic import ValidationError

        # 100 KB limit
        with pytest.raises(ValidationError, match="100 KB"):
            DetectionToolItem(
                name="big_tool",
                version="1.0.0",
                function_code="x" * 200_000,  # 200 KB
            )

    def test_plan_data_size_limit(self):
        from worker.bundles.bundle_schema import InvestigationPlanItem
        from pydantic import ValidationError

        big_plan = {"steps": [{"tool": "x"} for _ in range(5000)]}
        with pytest.raises(ValidationError, match="50 KB"):
            InvestigationPlanItem(
                plan_key="big_plan",
                version="1.0.0",
                plan_data=big_plan,
            )

    def test_anchor_limit_per_type(self):
        from worker.bundles.bundle_schema import BundleContents, RiskCalibrationAnchor
        from pydantic import ValidationError

        anchors = [
            RiskCalibrationAnchor(
                attack_type="brute_force",
                description=f"Anchor {i}",
                risk=50,
            )
            for i in range(11)  # Exceeds limit of 10
        ]
        with pytest.raises(ValidationError, match="Too many anchors"):
            BundleContents(risk_calibration=anchors)

    def test_sequence_number_monotonic(self):
        from worker.bundles.bundle_schema import (
            BundleManifest, check_sequence_and_expiry,
        )

        m = BundleManifest.model_validate({
            "bundle_id": "zvk-test-004",
            "sequence_number": 5,
            "version": "1.0.0",
            "tier": "community",
            "created_at": "2026-04-06T00:00:00Z",
            "contents": {},
        })
        # Sequence 5 should fail if last installed is 5
        with pytest.raises(ValueError, match="anti-replay"):
            check_sequence_and_expiry(m, last_installed_sequence=5, revoked_ids=set())

    def test_expired_bundle_rejected(self):
        from worker.bundles.bundle_schema import (
            BundleManifest, check_sequence_and_expiry,
        )

        m = BundleManifest.model_validate({
            "bundle_id": "zvk-test-005",
            "sequence_number": 10,
            "version": "1.0.0",
            "tier": "community",
            "created_at": "2026-04-06T00:00:00Z",
            "expires_at": "2020-01-01T00:00:00Z",  # Already expired
            "contents": {},
        })
        with pytest.raises(ValueError, match="expired"):
            check_sequence_and_expiry(m, last_installed_sequence=0, revoked_ids=set())

    def test_revoked_bundle_rejected(self):
        from worker.bundles.bundle_schema import (
            BundleManifest, check_sequence_and_expiry,
        )

        m = BundleManifest.model_validate({
            "bundle_id": "zvk-revoked-001",
            "sequence_number": 10,
            "version": "1.0.0",
            "tier": "community",
            "created_at": "2026-04-06T00:00:00Z",
            "contents": {},
        })
        with pytest.raises(ValueError, match="revoked"):
            check_sequence_and_expiry(
                m, last_installed_sequence=0,
                revoked_ids={"zvk-revoked-001"},
            )

    def test_valid_plan_item(self):
        from worker.bundles.bundle_schema import InvestigationPlanItem

        plan = InvestigationPlanItem(
            plan_key="test_attack",
            version="1.0.0",
            plan_data={
                "description": "Test attack plan",
                "plan": [
                    {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
                ],
            },
        )
        assert plan.plan_key == "test_attack"


# ── SAST Security Gate Tests ──────────────────────────────

class TestSASTGates:
    """SAST must block dangerous code patterns."""

    def test_safe_tool_passes(self):
        from worker.bundles.security import run_sast

        code = """
import re
import json

def detect_test(siem_event):
    raw = siem_event.get("raw_log", "")
    matches = re.findall(r"failed", raw, re.IGNORECASE)
    return {"risk_score": len(matches) * 10, "findings": matches}
"""
        result = run_sast(code, skip_runtime=True)
        assert result.safe is True
        assert 1 in result.phases_passed
        assert 2 in result.phases_passed

    def test_os_import_blocked(self):
        from worker.bundles.security import run_sast

        code = "import os\nos.system('rm -rf /')"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False
        assert any("os" in i.description for i in result.issues)

    def test_subprocess_blocked(self):
        from worker.bundles.security import run_sast

        code = "import subprocess\nsubprocess.run(['ls'])"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False

    def test_eval_blocked(self):
        from worker.bundles.security import run_sast

        code = "x = eval('1+1')"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False
        assert any("eval" in i.description for i in result.issues)

    def test_exec_blocked(self):
        from worker.bundles.security import run_sast

        code = "exec('import os')"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False

    def test_dunder_import_blocked(self):
        from worker.bundles.security import run_sast

        code = "mod = __import__('os')"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False

    def test_importlib_concat_blocked(self):
        from worker.bundles.security import run_sast

        code = """
import importlib
name = 'o' + 's'
mod = importlib.import_module(name)
"""
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False

    def test_getattr_concat_blocked(self):
        from worker.bundles.security import run_sast

        code = """
import builtins
fn = getattr(builtins, 'ev' + 'al')
fn('1+1')
"""
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False
        assert any("getattr" in i.description for i in result.issues)

    def test_base64_payload_warning(self):
        from worker.bundles.security import run_sast

        code = f'payload = "{("A" * 150)}"'
        result = run_sast(code, skip_runtime=True)
        # Should warn but not block (warning, not critical)
        warnings = [i for i in result.issues if i.severity == "warning"]
        assert len(warnings) >= 1

    def test_pickle_blocked(self):
        from worker.bundles.security import run_sast

        code = "import pickle\npickle.loads(data)"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False

    def test_socket_blocked(self):
        from worker.bundles.security import run_sast

        code = "import socket\ns = socket.socket()"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False

    def test_ctypes_blocked(self):
        from worker.bundles.security import run_sast

        code = "import ctypes\nctypes.cdll.LoadLibrary('libc.so.6')"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False

    def test_syntax_error_caught(self):
        from worker.bundles.security import run_sast

        code = "def broken(:\n  pass"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False
        assert any("Syntax error" in i.description for i in result.issues)

    def test_allowed_imports_pass(self):
        from worker.bundles.security import run_sast

        code = """
import json
import re
import datetime
import collections
import math
import hashlib
import ipaddress
import base64
from urllib.parse import urlparse
import csv
import statistics
"""
        result = run_sast(code, skip_runtime=True)
        assert result.safe is True

    def test_unknown_module_blocked(self):
        from worker.bundles.security import run_sast

        code = "import numpy"
        result = run_sast(code, skip_runtime=True)
        assert result.safe is False
        assert any("allowlist" in i.description for i in result.issues)


# ── Diff/Preview Tests ────────────────────────────────────

class TestBundleDiff:
    """Test bundle_diff preview output."""

    def test_diff_shows_new_plan(self):
        from worker.bundles.bundle_schema import BundleManifest, bundle_diff

        m = BundleManifest.model_validate({
            "bundle_id": "zvk-test-diff",
            "sequence_number": 1,
            "version": "1.0.0",
            "tier": "community",
            "created_at": "2026-04-06T00:00:00Z",
            "contents": {
                "investigation_plans": [{
                    "plan_key": "new_attack",
                    "version": "1.0.0",
                    "plan_data": {"plan": []},
                }],
            },
        })
        lines = bundle_diff(m, existing={"plans": {}})
        assert any("[NEW]" in l and "new_attack" in l for l in lines)

    def test_diff_shows_modify(self):
        from worker.bundles.bundle_schema import BundleManifest, bundle_diff

        m = BundleManifest.model_validate({
            "bundle_id": "zvk-test-diff2",
            "sequence_number": 2,
            "version": "1.0.0",
            "tier": "community",
            "created_at": "2026-04-06T00:00:00Z",
            "contents": {
                "investigation_plans": [{
                    "plan_key": "brute_force",
                    "version": "2.0.0",
                    "plan_data": {"plan": []},
                }],
            },
        })
        lines = bundle_diff(
            m, existing={"plans": {"brute_force": "1.0.0"}},
        )
        assert any("[MODIFY]" in l and "brute_force" in l for l in lines)

    def test_diff_warns_nonexistent_replaces(self):
        from worker.bundles.bundle_schema import BundleManifest, bundle_diff

        m = BundleManifest.model_validate({
            "bundle_id": "zvk-test-diff3",
            "sequence_number": 3,
            "version": "1.0.0",
            "tier": "community",
            "created_at": "2026-04-06T00:00:00Z",
            "contents": {
                "investigation_plans": [{
                    "plan_key": "new_plan",
                    "version": "1.0.0",
                    "plan_data": {"plan": []},
                    "replaces": "nonexistent_plan",
                }],
            },
        })
        lines = bundle_diff(m, existing={"plans": {}})
        assert any("WARNING" in l and "nonexistent_plan" in l for l in lines)


# ── Semver Comparison Tests ───────────────────────────────

class TestSemver:
    """Test version comparison logic."""

    def test_higher_version_wins(self):
        from worker.bundles.importer import _semver_gte

        assert _semver_gte("2.0.0", "1.0.0") is True
        assert _semver_gte("1.1.0", "1.0.0") is True
        assert _semver_gte("1.0.1", "1.0.0") is True

    def test_same_version(self):
        from worker.bundles.importer import _semver_gte

        assert _semver_gte("1.0.0", "1.0.0") is True

    def test_lower_version(self):
        from worker.bundles.importer import _semver_gte

        assert _semver_gte("1.0.0", "2.0.0") is False
        assert _semver_gte("1.0.0", "1.1.0") is False
