#!/bin/bash
# Auto-generates a complete codebase inventory as docs/MANIFEST.json
# Works on Windows Git Bash (no Python dependency on host)
# Run after every significant commit

set -e
cd "$(git rev-parse --show-toplevel)"

echo "Generating codebase manifest..."

GIT_COMMIT=$(git rev-parse --short HEAD)
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
GENERATED_AT=$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)

# --- Counts ---
API_ROUTES=$(grep -cE '\.(GET|POST|PUT|PATCH|DELETE)\("' api/main.go 2>/dev/null || echo 0)
TOOL_COUNT=$(grep -c '"function"' worker/tools/catalog.py 2>/dev/null || echo 0)
DETECTOR_COUNT=$(grep -c '^def detect_' worker/tools/detection.py 2>/dev/null || echo 0)
PLAN_COUNT=$(grep -c '"plan"' worker/tools/investigation_plans.json 2>/dev/null || echo 0)
MIGRATION_COUNT=$(ls migrations/*.sql 2>/dev/null | wc -l | tr -d ' ')
TEST_COUNT=$(ls worker/tests/test_*.py 2>/dev/null | wc -l | tr -d ' ')
SCANNER_PATTERNS=$(grep -c "r'" worker/stages/ingest.py 2>/dev/null || echo 0)
SIGNAL_BOOST=$(grep -c '(r"' worker/stages/assess.py 2>/dev/null || echo 0)
PY_FILES=$(find worker -name '*.py' 2>/dev/null | wc -l | tr -d ' ')
GO_FILES=$(find api cmd -name '*.go' 2>/dev/null | wc -l | tr -d ' ')
TSX_FILES=$(find web-admin/src dashboard/src -name '*.tsx' -o -name '*.ts' 2>/dev/null | wc -l | tr -d ' ')
DOCKER_SERVICES=$(grep -cE '^  [a-z]' docker-compose.yml 2>/dev/null || echo 0)

# --- Lists ---
ROUTES_JSON=$(grep -oE '\.(GET|POST|PUT|PATCH|DELETE)\("([^"]+)"' api/main.go 2>/dev/null | \
  sed 's/\.\(.*\)("\(.*\)"/{"method":"\1","path":"\2"}/' | \
  paste -sd',' | sed 's/^/[/' | sed 's/$/]/')
[ -z "$ROUTES_JSON" ] && ROUTES_JSON="[]"

TOOLS_JSON=$(grep -E '^\s+"[a-z_]+": \{"function"' worker/tools/catalog.py 2>/dev/null | \
  sed 's/.*"\([a-z_]*\)": {"function".*/"\1"/' | paste -sd',' | sed 's/^/[/' | sed 's/$/]/')
[ -z "$TOOLS_JSON" ] && TOOLS_JSON="[]"

PLANS_JSON=$(grep -E '^\s+"[a-z_]+": \{' worker/tools/investigation_plans.json 2>/dev/null | \
  sed 's/.*"\([a-z_]*\)": {.*/"\1"/' | paste -sd',' | sed 's/^/[/' | sed 's/$/]/')
[ -z "$PLANS_JSON" ] && PLANS_JSON="[]"

MIGRATIONS_JSON=$(ls migrations/*.sql 2>/dev/null | xargs -I{} basename {} | \
  sed 's/.*/"&"/' | paste -sd',' | sed 's/^/[/' | sed 's/$/]/')
[ -z "$MIGRATIONS_JSON" ] && MIGRATIONS_JSON="[]"

TESTS_JSON=$(ls worker/tests/test_*.py 2>/dev/null | xargs -I{} basename {} | \
  sed 's/.*/"&"/' | paste -sd',' | sed 's/^/[/' | sed 's/$/]/')
[ -z "$TESTS_JSON" ] && TESTS_JSON="[]"

DETECTORS_JSON=$(grep '^def detect_' worker/tools/detection.py 2>/dev/null | \
  sed 's/def \(detect_[a-z_]*\).*/"\1"/' | paste -sd',' | sed 's/^/[/' | sed 's/$/]/')
[ -z "$DETECTORS_JSON" ] && DETECTORS_JSON="[]"

COMPONENTS_JSON=$(ls web-admin/src/components/*.tsx dashboard/src/components/*.tsx dashboard/src/pages/*.tsx 2>/dev/null | \
  xargs -I{} basename {} | sort -u | sed 's/.*/"&"/' | paste -sd',' | sed 's/^/[/' | sed 's/$/]/')
[ -z "$COMPONENTS_JSON" ] && COMPONENTS_JSON="[]"

# --- Write JSON ---
cat > docs/MANIFEST.json << MANIFEST_EOF
{
  "generated_at": "${GENERATED_AT}",
  "git_commit": "${GIT_COMMIT}",
  "git_branch": "${GIT_BRANCH}",
  "summary": {
    "api_route_count": ${API_ROUTES},
    "tool_count": ${TOOL_COUNT},
    "detector_count": ${DETECTOR_COUNT},
    "plan_count": ${PLAN_COUNT},
    "migration_count": ${MIGRATION_COUNT},
    "test_file_count": ${TEST_COUNT},
    "content_scanner_patterns": ${SCANNER_PATTERNS},
    "signal_boost_patterns": ${SIGNAL_BOOST},
    "python_files": ${PY_FILES},
    "go_files": ${GO_FILES},
    "frontend_files": ${TSX_FILES},
    "docker_services": ${DOCKER_SERVICES}
  },
  "api_routes": ${ROUTES_JSON},
  "tools": ${TOOLS_JSON},
  "detectors": ${DETECTORS_JSON},
  "investigation_plans": ${PLANS_JSON},
  "migrations": ${MIGRATIONS_JSON},
  "test_files": ${TESTS_JSON},
  "dashboard_components": ${COMPONENTS_JSON},
  "feature_flags": ["ZOVARK_EXECUTION_MODE","ZOVARK_PARALLEL_TOOLS_ENABLED","ZOVARK_MAX_PARALLEL_TOOLS","ZOVARK_FAST_FILL","ZOVARK_MODE"]
}
MANIFEST_EOF

echo "Manifest written to docs/MANIFEST.json"
echo "---"
echo "Commit:     ${GIT_COMMIT} (${GIT_BRANCH})"
echo "API routes: ${API_ROUTES}"
echo "Tools:      ${TOOL_COUNT}"
echo "Detectors:  ${DETECTOR_COUNT}"
echo "Plans:      ${PLAN_COUNT}"
echo "Migrations: ${MIGRATION_COUNT}"
echo "Tests:      ${TEST_COUNT}"
echo "Scanner:    ${SCANNER_PATTERNS} patterns"
echo "Boost:      ${SIGNAL_BOOST} patterns"
echo "Services:   ${DOCKER_SERVICES}"
echo "Python:     ${PY_FILES} files"
echo "Go:         ${GO_FILES} files"
echo "Frontend:   ${TSX_FILES} files"
