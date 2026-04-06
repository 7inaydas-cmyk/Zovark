#!/bin/bash
# Zovark Architecture Linter
# Checks that code matches PRD invariants.
# Run: bash scripts/lint_architecture.sh
# Run after: every sprint completion, before every merge

PASS=0
FAIL=0
WARN=0

echo "ZOVARK ARCHITECTURE LINT"
echo "================================"

# --- CHECK 1: investigation_workflow.py unmodified since v3.2.1 ---
WORKFLOW_FILE="worker/stages/investigation_workflow.py"
if [ -f "$WORKFLOW_FILE" ]; then
    # Check if modified since v3.2.1 tag (the PRD baseline), not since the dawn of time
    BASELINE_TAG="v3.2.1"
    CHANGES_SINCE=$(git log "$BASELINE_TAG"..HEAD --oneline -- "$WORKFLOW_FILE" 2>/dev/null | head -1)
    if [ -z "$CHANGES_SINCE" ]; then
        echo "  PASS  investigation_workflow.py: unmodified since $BASELINE_TAG"
        ((PASS++)) || true
    else
        echo "  FAIL  investigation_workflow.py: MODIFIED since $BASELINE_TAG"
        echo "        $CHANGES_SINCE"
        ((FAIL++)) || true
    fi
else
    echo "  WARN  investigation_workflow.py: file not found"
    ((WARN++)) || true
fi

# --- CHECK 2: Two-model architecture preserved ---
if grep -q "ZOVARK_LLM_ENDPOINT_FAST\|LLM_ENDPOINT_FAST" worker/stages/llm_gateway.py 2>/dev/null && \
   grep -q "ZOVARK_LLM_ENDPOINT_CODE\|LLM_ENDPOINT_CODE" worker/stages/llm_gateway.py 2>/dev/null; then
    echo "  PASS  Two-model architecture: FAST/CODE endpoints present"
    ((PASS++)) || true
else
    echo "  FAIL  Two-model architecture: missing FAST or CODE endpoint"
    ((FAIL++)) || true
fi

# --- CHECK 3: No cloud imports in pipeline stages ---
CLOUD_IMPORTS=$(grep -rn "import boto3\|import azure\|from google.cloud\|import openai" \
    worker/stages/ 2>/dev/null || true)
if [ -z "$CLOUD_IMPORTS" ]; then
    echo "  PASS  Pipeline stages: no cloud SDK imports"
    ((PASS++)) || true
else
    echo "  FAIL  Pipeline stages: cloud SDK import found"
    echo "        $CLOUD_IMPORTS"
    ((FAIL++)) || true
fi

# --- CHECK 4: Tenant isolation in intelligence layer ---
# Only check actual SQL strings (lines containing quotes + SQL keywords), skip Python logic
MISSING_TENANT=$(grep -rn '"\(SELECT\|INSERT\|UPDATE\|DELETE\)' \
    worker/intelligence/ 2>/dev/null | \
    grep -iv "tenant_id\|instance.scoped\|-- no tenant\|#.*tenant\|risk_calibration\|investigation_plans_db\|installed_bundles\|revoked_bundles" || true)
if [ -z "$MISSING_TENANT" ]; then
    echo "  PASS  Intelligence layer: tenant_id in SQL queries"
    ((PASS++)) || true
else
    MISSING_COUNT=$(echo "$MISSING_TENANT" | wc -l)
    echo "  WARN  Intelligence layer: $MISSING_COUNT SQL queries may lack tenant_id (review manually)"
    ((WARN++)) || true
fi

# --- CHECK 5: SAST blocks dangerous imports ---
if [ -f "worker/bundles/security.py" ]; then
    SAST_OK=true
    for module in "os" "subprocess" "sys" "socket" "ctypes"; do
        if ! grep -q "\"$module\"" worker/bundles/security.py 2>/dev/null; then
            echo "  FAIL  SAST blocklist: missing '$module'"
            ((FAIL++)) || true
            SAST_OK=false
        fi
    done
    if [ "$SAST_OK" = true ]; then
        echo "  PASS  SAST blocklist: all dangerous modules listed"
        ((PASS++)) || true
    fi
else
    echo "  WARN  SAST: security.py not found"
    ((WARN++)) || true
fi

# --- CHECK 6: Bundle detection tools NOT hot-loaded ---
HOT_LOAD=$(grep -rn "hot.load\|hot_load\|reload.*catalog\|register.*runtime" \
    worker/bundles/importer.py 2>/dev/null || true)
if [ -z "$HOT_LOAD" ]; then
    echo "  PASS  Bundle importer: no hot-loading of detection tools"
    ((PASS++)) || true
else
    echo "  FAIL  Bundle importer: possible hot-loading detected"
    echo "        $HOT_LOAD"
    ((FAIL++)) || true
fi

# --- CHECK 7: Plans are instance-scoped ---
if [ -f "migrations/066_template_sync_engine.sql" ]; then
    # Check that investigation_plans_db does NOT have tenant_id
    PLANS_TENANT=$(grep -A20 "investigation_plans_db" migrations/066_template_sync_engine.sql 2>/dev/null | grep "tenant_id" || true)
    if [ -z "$PLANS_TENANT" ]; then
        echo "  PASS  investigation_plans_db: instance-scoped (no tenant_id)"
        ((PASS++)) || true
    else
        echo "  FAIL  investigation_plans_db: has tenant_id (should be instance-scoped)"
        ((FAIL++)) || true
    fi
else
    echo "  WARN  Migration 066 not found"
    ((WARN++)) || true
fi

# --- CHECK 8: License check is fail-closed ---
if [ -f "worker/bundles/license.py" ]; then
    if grep -q "return False\|fail.closed\|deny" worker/bundles/license.py 2>/dev/null; then
        echo "  PASS  License manager: fail-closed on error"
        ((PASS++)) || true
    else
        echo "  WARN  License manager: verify fail-closed behavior manually"
        ((WARN++)) || true
    fi
else
    echo "  WARN  License manager: not yet implemented (Sprint C3)"
    ((WARN++)) || true
fi

# --- CHECK 9: Additive-only migration ---
if [ -f "migrations/066_template_sync_engine.sql" ]; then
    DESTRUCTIVE=$(grep -in "DROP TABLE\|DROP COLUMN\|ALTER.*DROP\|TRUNCATE" \
        migrations/066_template_sync_engine.sql 2>/dev/null | grep -v "^.*:--" || true)
    if [ -z "$DESTRUCTIVE" ]; then
        echo "  PASS  Migration 066: additive-only (no destructive DDL)"
        ((PASS++)) || true
    else
        echo "  FAIL  Migration 066: destructive DDL found"
        echo "        $DESTRUCTIVE"
        ((FAIL++)) || true
    fi
else
    echo "  WARN  Migration 066 not found"
    ((WARN++)) || true
fi

# --- CHECK 10: Regression suite includes Path C ---
if grep -q "unusual_network_traffic" autoresearch/cycle10/verify_all.sh 2>/dev/null; then
    echo "  PASS  Regression suite: includes Path C (unusual_network_traffic)"
    ((PASS++)) || true
else
    echo "  FAIL  Regression suite: missing Path C coverage"
    ((FAIL++)) || true
fi

# --- CHECK 11: No HTTP self-calls in Go API ---
SELF_CALLS=$(grep -rn "localhost:8090\|127\.0\.0\.1:8090" \
    api/ 2>/dev/null | grep -v "_test.go\|// \|//" || true)
if [ -z "$SELF_CALLS" ]; then
    echo "  PASS  Go API: no HTTP self-calls"
    ((PASS++)) || true
else
    echo "  WARN  Go API: possible HTTP self-calls (verify they bypass rate limiter)"
    echo "        $(echo "$SELF_CALLS" | head -3)"
    ((WARN++)) || true
fi

# --- CHECK 12: Copilot doesn't starve pipeline ---
if [ -f "worker/intelligence/copilot.py" ]; then
    if grep -qi "semaphore\|priority\|Semaphore" worker/intelligence/copilot.py 2>/dev/null; then
        echo "  PASS  Copilot: semaphore/priority control present"
        ((PASS++)) || true
    else
        echo "  WARN  Copilot: no semaphore control found"
        ((WARN++)) || true
    fi
else
    echo "  WARN  Copilot: not yet implemented (Sprint C2)"
    ((WARN++)) || true
fi

# --- SUMMARY ---
echo ""
echo "================================"
echo "RESULTS: $PASS passed, $FAIL failed, $WARN warnings"

if [ $FAIL -gt 0 ]; then
    echo "ARCHITECTURAL DRIFT DETECTED -- fix before merging"
    exit 1
elif [ $WARN -gt 0 ]; then
    echo "WARNINGS -- review before merging"
    exit 0
else
    echo "ALL CLEAN -- architecture matches PRD"
    exit 0
fi
