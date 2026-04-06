"""
Tests for the Remediation Engine (Sprint C1).
Covers: deterministic rules, circuit breaker, rate limiter, verification state.
"""
import time
import pytest


class TestSuggestActions:
    """Test deterministic remediation suggestions."""

    def test_brute_force_suggestions(self):
        from worker.intelligence.remediation import suggest_actions

        result = suggest_actions("brute_force", risk_score=85, verdict="true_positive")
        assert len(result) == 3
        assert result[0]["action_type"] == "block"
        assert result[0]["priority"] >= 90  # boosted by high risk

    def test_benign_verdict_returns_false_positive(self):
        from worker.intelligence.remediation import suggest_actions

        result = suggest_actions("brute_force", risk_score=10, verdict="benign")
        assert len(result) == 1
        assert result[0]["action_type"] == "false_positive"

    def test_inconclusive_verdict(self):
        from worker.intelligence.remediation import suggest_actions

        result = suggest_actions("ransomware_triage", risk_score=50, verdict="inconclusive")
        assert len(result) == 1
        assert result[0]["action_type"] == "investigate_further"

    def test_unknown_attack_type_uses_defaults(self):
        from worker.intelligence.remediation import suggest_actions

        result = suggest_actions("completely_new_attack", risk_score=70, verdict="true_positive")
        assert len(result) == 2
        assert result[0]["action_type"] == "investigate_further"

    def test_critical_risk_boosts_priority(self):
        from worker.intelligence.remediation import suggest_actions

        low = suggest_actions("kerberoasting", risk_score=40, verdict="suspicious")
        high = suggest_actions("kerberoasting", risk_score=95, verdict="true_positive")
        # High risk should have higher priority than low risk
        assert high[0]["priority"] > low[0]["priority"]

    def test_iocs_boost_priority(self):
        from worker.intelligence.remediation import suggest_actions

        no_iocs = suggest_actions("dns_exfiltration", risk_score=80, verdict="true_positive")
        with_iocs = suggest_actions(
            "dns_exfiltration", risk_score=80, verdict="true_positive",
            iocs=[{"type": "ip", "value": "1.2.3.4"}] * 5,
        )
        assert with_iocs[0]["priority"] >= no_iocs[0]["priority"]

    def test_all_attack_types_have_rules(self):
        from worker.intelligence.remediation import REMEDIATION_RULES

        # Every rule must have required fields
        for attack_type, rules in REMEDIATION_RULES.items():
            assert len(rules) >= 2, f"{attack_type} has too few rules"
            for rule in rules:
                assert "action_type" in rule
                assert "description" in rule
                assert "priority" in rule
                assert 0 < rule["priority"] <= 100

    def test_suggestions_sorted_by_priority(self):
        from worker.intelligence.remediation import suggest_actions

        result = suggest_actions("golden_ticket", risk_score=90, verdict="true_positive")
        priorities = [s["priority"] for s in result]
        assert priorities == sorted(priorities, reverse=True)


class TestCircuitBreaker:
    """Test verification circuit breaker (3 per type per 24h)."""

    def test_first_attempt_allowed(self):
        from worker.intelligence.remediation import (
            check_circuit_breaker, _tenant_states,
        )
        _tenant_states.clear()

        ok, msg = check_circuit_breaker("test-tenant-cb1", "brute_force")
        assert ok is True
        assert msg == ""

    def test_opens_after_three_attempts(self):
        from worker.intelligence.remediation import (
            check_circuit_breaker, record_verification, _tenant_states,
        )
        _tenant_states.clear()

        tenant = "test-tenant-cb2"
        for _ in range(3):
            record_verification(tenant, "brute_force")

        ok, msg = check_circuit_breaker(tenant, "brute_force")
        assert ok is False
        assert "circuit breaker open" in msg

    def test_different_attack_types_independent(self):
        from worker.intelligence.remediation import (
            check_circuit_breaker, record_verification, _tenant_states,
        )
        _tenant_states.clear()

        tenant = "test-tenant-cb3"
        for _ in range(3):
            record_verification(tenant, "brute_force")

        # brute_force is blocked
        ok, _ = check_circuit_breaker(tenant, "brute_force")
        assert ok is False

        # phishing is still allowed
        ok, _ = check_circuit_breaker(tenant, "phishing_investigation")
        assert ok is True

    def test_resets_after_24h(self):
        from worker.intelligence.remediation import (
            check_circuit_breaker, _tenant_states, _get_state,
        )
        _tenant_states.clear()

        tenant = "test-tenant-cb4"
        state = _get_state(tenant)
        # Add 3 attempts from 25 hours ago
        old_time = time.time() - 90000  # 25 hours ago
        state.attempts["brute_force"] = [old_time, old_time, old_time]

        ok, _ = check_circuit_breaker(tenant, "brute_force")
        assert ok is True  # Old attempts expired


class TestRateLimiter:
    """Test synthetic alert rate limiter (10 per hour)."""

    def test_under_limit_allowed(self):
        from worker.intelligence.remediation import (
            check_circuit_breaker, _tenant_states,
        )
        _tenant_states.clear()

        ok, _ = check_circuit_breaker("test-tenant-rl1", "brute_force")
        assert ok is True

    def test_blocks_at_ten(self):
        from worker.intelligence.remediation import (
            check_circuit_breaker, record_verification, _tenant_states,
        )
        _tenant_states.clear()

        tenant = "test-tenant-rl2"
        for _ in range(10):
            record_verification(tenant, "mixed_type")

        ok, msg = check_circuit_breaker(tenant, "different_type")
        assert ok is False
        assert "rate limit" in msg

    def test_resets_after_one_hour(self):
        from worker.intelligence.remediation import (
            check_circuit_breaker, _tenant_states, _get_state,
        )
        _tenant_states.clear()

        tenant = "test-tenant-rl3"
        state = _get_state(tenant)
        old_time = time.time() - 3700  # Just over 1 hour ago
        state.synthetic_timestamps = [old_time] * 10

        ok, _ = check_circuit_breaker(tenant, "brute_force")
        assert ok is True


class TestVerificationStats:
    """Test verification state reporting."""

    def test_empty_stats(self):
        from worker.intelligence.remediation import (
            get_verification_stats, _tenant_states,
        )
        _tenant_states.clear()

        stats = get_verification_stats("test-tenant-vs1")
        assert stats["synthetic_hour"] == 0
        assert stats["rate_limited"] is False
        assert stats["per_type"] == {}

    def test_stats_after_attempts(self):
        from worker.intelligence.remediation import (
            get_verification_stats, record_verification, _tenant_states,
        )
        _tenant_states.clear()

        tenant = "test-tenant-vs2"
        record_verification(tenant, "brute_force")
        record_verification(tenant, "brute_force")
        record_verification(tenant, "phishing_investigation")

        stats = get_verification_stats(tenant)
        assert stats["synthetic_hour"] == 3
        assert stats["per_type"]["brute_force"]["attempts_24h"] == 2
        assert stats["per_type"]["phishing_investigation"]["attempts_24h"] == 1
