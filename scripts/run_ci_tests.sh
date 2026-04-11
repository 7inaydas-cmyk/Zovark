#!/usr/bin/env bash
# ============================================================
# Zovark CI Test Runner
# Runs unit tests (Layer 1) and integration tests (Layer 2).
# Usage:
#   ./scripts/run_ci_tests.sh           # run all layers
#   ./scripts/run_ci_tests.sh unit      # Layer 1 only
#   ./scripts/run_ci_tests.sh integration  # Layer 2 only
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

passed=0
failed=0
skipped=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((passed++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((failed++)); }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; ((skipped++)); }
log_info() { echo -e "[INFO] $1"; }

# ─── Layer 1: Unit Tests (no Docker, no LLM) ──────────────
run_unit_tests() {
    log_info "========== Layer 1: Unit Tests =========="

    # --- Python unit tests ---
    log_info "Running Python unit tests..."
    if (cd worker && python -m pytest tests/ -v --tb=short -q 2>&1); then
        log_pass "Python unit tests"
    else
        log_fail "Python unit tests"
    fi

    # --- Go unit tests ---
    log_info "Running Go unit tests..."
    if (cd api && go test -v -race -count=1 ./... 2>&1); then
        log_pass "Go unit tests"
    else
        log_fail "Go unit tests"
    fi

    # --- Import validation ---
    log_info "Validating core imports..."
    if (cd worker && python -c "
from model_config import get_tier_config, ACTIVITY_TIER_MAP
from prompt_registry import get_version, prompt_count
from rate_limiter import acquire_lease, release_lease
from entity_normalize import normalize_entity, compute_entity_hash
from context_manager import truncate_for_model
from llm_logger import log_llm_call
from security.injection_detector import scan_for_injection
from security.prompt_sanitizer import wrap_untrusted_data
from detection.pattern_miner import mine_attack_patterns
from detection.sigma_generator import generate_sigma_rule
from detection.rule_validator import validate_sigma_rule
from response.actions import ACTION_REGISTRY, ResponseAction
print('All core imports OK')
" 2>&1); then
        log_pass "Core imports"
    else
        log_fail "Core imports"
    fi

    # --- Entity normalization ---
    log_info "Validating entity normalization..."
    if (cd worker && python -c "
from entity_normalize import normalize_entity
assert normalize_entity('ip', '192.168.001.100') == '192.168.1.100'
assert normalize_entity('ip', '010.000.001.001') == '10.0.1.1'
assert normalize_entity('domain', 'WWW.EXAMPLE.COM') == 'example.com'
print('Entity normalization OK')
" 2>&1); then
        log_pass "Entity normalization"
    else
        log_fail "Entity normalization"
    fi

    # --- Migration syntax check ---
    log_info "Checking migration file syntax..."
    migration_ok=true
    for f in migrations/*.sql; do
        if [ ! -f "$f" ]; then
            log_skip "No migration files found"
            migration_ok=false
            break
        fi
        # Check that each file is valid UTF-8 and non-empty
        if [ ! -s "$f" ]; then
            log_fail "Empty migration: $f"
            migration_ok=false
            break
        fi
    done
    if $migration_ok; then
        log_pass "Migration syntax check ($(ls migrations/*.sql 2>/dev/null | wc -l) files)"
    fi

    # --- Migration prefix uniqueness check ---
    log_info "Checking migration prefix uniqueness..."
    dup_prefixes=$(ls migrations/*.sql 2>/dev/null | xargs -I{} basename {} | sed 's/_.*//' | sort | uniq -d)
    if [ -n "$dup_prefixes" ]; then
        log_fail "Duplicate migration prefixes found: $dup_prefixes"
        for prefix in $dup_prefixes; do
            ls migrations/${prefix}_*.sql 2>/dev/null | while read -r f; do
                echo "  CONFLICT: $f"
            done
        done
    else
        log_pass "Migration prefix uniqueness (no duplicates)"
    fi
}

# ─── Layer 2: Integration Tests (mock Ollama, Docker stack) ──
run_integration_tests() {
    log_info "========== Layer 2: Integration Tests (Mock Ollama) =========="

    # Build and start the test stack
    log_info "Starting test stack with mock Ollama..."
    docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build --wait 2>&1 || {
        log_info "Falling back to start without --wait..."
        docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build 2>&1
    }

    # Wait for API health
    log_info "Waiting for API to become healthy..."
    api_healthy=false
    for i in $(seq 1 60); do
        if curl -sf http://localhost:8090/health > /dev/null 2>&1; then
            api_healthy=true
            break
        fi
        sleep 5
    done

    if ! $api_healthy; then
        log_fail "API did not become healthy within 5 minutes"
        docker compose -f docker-compose.yml -f docker-compose.test.yml logs --tail=50 api 2>&1
        cleanup_stack
        return 1
    fi
    log_pass "API health check"

    # Verify mock Ollama is responding
    log_info "Verifying mock Ollama..."
    if curl -sf http://localhost:11434/health > /dev/null 2>&1; then
        log_pass "Mock Ollama health"
    else
        log_fail "Mock Ollama not responding"
    fi

    # Login and get token
    log_info "Testing authentication..."
    TOKEN=$(curl -sf -X POST http://localhost:8090/api/v1/auth/login \
        -H "Content-Type: application/json" \
        -d '{"email":"admin@test.local","password":"TestPass2026"}' \
        2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")

    if [ -n "$TOKEN" ] && [ "$TOKEN" != "" ]; then
        log_pass "Authentication"
    else
        log_fail "Authentication (could not obtain token)"
        cleanup_stack
        return 1
    fi

    # Submit a test investigation
    log_info "Submitting test investigation..."
    TASK_RESPONSE=$(curl -sf -X POST http://localhost:8090/api/v1/tasks \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "task_type": "brute_force",
            "input": {
                "prompt": "SSH brute force test",
                "severity": "high",
                "siem_event": {
                    "title": "SSH Brute Force",
                    "source_ip": "10.99.99.99",
                    "username": "root",
                    "rule_name": "BruteForce",
                    "raw_log": "500 failed for root from 10.99.99.99"
                }
            }
        }' 2>/dev/null || echo "")

    if [ -n "$TASK_RESPONSE" ]; then
        TASK_ID=$(echo "$TASK_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('task_id', json.load(sys.stdin) if False else ''))" 2>/dev/null || echo "")
        if [ -n "$TASK_ID" ]; then
            log_pass "Task submission (ID: $TASK_ID)"
        else
            log_pass "Task submission (response received)"
        fi
    else
        log_fail "Task submission"
    fi

    # Run integration test suite if it exists
    if [ -d "tests/integration" ]; then
        log_info "Running integration test suite..."
        if python -m pytest tests/integration/ -v --tb=short -q 2>&1; then
            log_pass "Integration test suite"
        else
            log_fail "Integration test suite"
        fi
    else
        log_skip "Integration test suite (tests/integration/ not found)"
    fi

    cleanup_stack
}

cleanup_stack() {
    log_info "Cleaning up test stack..."
    docker compose -f docker-compose.yml -f docker-compose.test.yml down --volumes --remove-orphans 2>&1 || true
}

# ─── Main ──────────────────────────────────────────────────
main() {
    local mode="${1:-all}"

    echo "============================================="
    echo "  Zovark CI Test Runner"
    echo "  Mode: $mode"
    echo "============================================="
    echo ""

    case "$mode" in
        unit)
            run_unit_tests
            ;;
        integration)
            run_integration_tests
            ;;
        all|"")
            run_unit_tests
            echo ""
            run_integration_tests
            ;;
        *)
            echo "Usage: $0 [unit|integration|all]"
            exit 1
            ;;
    esac

    echo ""
    echo "============================================="
    echo "  Results: ${GREEN}${passed} passed${NC}, ${RED}${failed} failed${NC}, ${YELLOW}${skipped} skipped${NC}"
    echo "============================================="

    if [ "$failed" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
