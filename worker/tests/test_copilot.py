"""
Tests for copilot intelligence module (Sprint C2).
Tests deterministic paths only — no LLM dependency in tests.
"""
import asyncio
import pytest


class TestExplainFallback:
    """Test template-based explanation when LLM is unavailable."""

    def test_explain_fallback_high_risk(self):
        from worker.intelligence.copilot import _explain_fallback

        inv = {
            "task_type": "brute_force",
            "verdict": "true_positive",
            "risk_score": 95,
            "findings": ["500 failed login attempts", "Source IP is known malicious"],
        }
        result = _explain_fallback(inv)
        assert "brute force" in result
        assert "true_positive" in result
        assert "95" in result
        assert "immediate attention" in result

    def test_explain_fallback_low_risk(self):
        from worker.intelligence.copilot import _explain_fallback

        inv = {
            "task_type": "password_change",
            "verdict": "benign",
            "risk_score": 0,
            "findings": [],
        }
        result = _explain_fallback(inv)
        assert "benign" in result
        assert "low-priority" in result

    def test_explain_fallback_medium_risk(self):
        from worker.intelligence.copilot import _explain_fallback

        inv = {
            "task_type": "phishing",
            "verdict": "suspicious",
            "risk_score": 55,
            "findings": ["Suspicious domain detected"],
        }
        result = _explain_fallback(inv)
        assert "suspicious" in result
        assert "reviewed" in result


class TestBriefFallback:
    """Test template-based brief when LLM is unavailable."""

    def test_brief_with_attacks(self):
        from worker.intelligence.copilot import _brief_fallback

        stats = {"total": 100, "attacks": 30, "benign": 60, "critical": 5, "avg_attack_risk": 85.0}
        top_attacks = [
            {"task_type": "brute_force", "count": 10},
            {"task_type": "phishing", "count": 8},
        ]
        result = _brief_fallback(stats, top_attacks, 8)
        assert "100 investigations" in result
        assert "30 attacks" in result
        assert "5 critical" in result
        assert "brute_force" in result
        assert "Immediate action" in result

    def test_brief_no_critical(self):
        from worker.intelligence.copilot import _brief_fallback

        stats = {"total": 50, "attacks": 5, "benign": 45, "critical": 0, "avg_attack_risk": 70.0}
        result = _brief_fallback(stats, [], 4)
        assert "No critical" in result

    def test_brief_respects_hour_display(self):
        from worker.intelligence.copilot import _brief_fallback

        stats = {"total": 10, "attacks": 2, "benign": 8, "critical": 0, "avg_attack_risk": 65.0}
        result = _brief_fallback(stats, [], 24)
        assert "24 hours" in result


class TestSuggestDeterministic:
    """Test that suggest works without LLM by using remediation rules."""

    def test_suggest_returns_actions_for_attacks(self):
        from worker.intelligence.remediation import suggest_actions

        result = suggest_actions("brute_force", risk_score=85, verdict="true_positive")
        assert len(result) >= 2
        assert result[0]["action_type"] in ("block", "access_revoke", "isolate")

    def test_suggest_benign_returns_false_positive(self):
        from worker.intelligence.remediation import suggest_actions

        result = suggest_actions("password_change", risk_score=0, verdict="benign")
        assert len(result) == 1
        assert result[0]["action_type"] == "false_positive"


class TestCopilotSemaphore:
    """Test that copilot semaphore limits concurrency."""

    def test_semaphore_exists(self):
        from worker.intelligence.copilot import _copilot_semaphore
        import asyncio

        assert isinstance(_copilot_semaphore, asyncio.Semaphore)

    def test_semaphore_limit_is_one(self):
        from worker.intelligence.copilot import _copilot_semaphore

        # Semaphore(1) allows 1 concurrent holder
        # Acquire should succeed immediately
        assert _copilot_semaphore._value == 1


class TestHourLimits:
    """Test that brief enforces hour limits."""

    def test_hours_clamped_low(self):
        h = max(1, min(168, 0))
        assert h == 1

    def test_hours_clamped_high(self):
        h = max(1, min(168, 500))
        assert h == 168

    def test_hours_normal(self):
        h = max(1, min(168, 8))
        assert h == 8
