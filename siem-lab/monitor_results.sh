#!/usr/bin/env bash
# ============================================================
# ZOVARK SIEM Lab — Live Results Monitor
# ============================================================
# Polls the PostgreSQL database every 15 seconds and displays
# live investigation results from the Zovark pipeline.
#
# Usage:
#   ./siem-lab/monitor_results.sh              # monitor recent tasks (last 1 hour)
#   ./siem-lab/monitor_results.sh --all        # monitor all tasks
#   ./siem-lab/monitor_results.sh --watch      # continuous 15s refresh (default)
#   ./siem-lab/monitor_results.sh --once       # single snapshot, no refresh
#   ./siem-lab/monitor_results.sh --tail 20    # show last 20 tasks
#   ./siem-lab/monitor_results.sh --api        # use API polling instead of DB
#
# Prerequisites:
#   docker compose up -d (postgres + api running)
# ============================================================

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────
POLL_INTERVAL="${POLL_INTERVAL:-15}"
DB_CONTAINER="${DB_CONTAINER:-zovark-postgres}"
DB_USER="${DB_USER:-zovark}"
DB_NAME="${DB_NAME:-zovark}"
DB_PASSWORD="${DB_PASSWORD:-zovark_dev_2026}"
ZOVARK_API="${ZOVARK_API:-http://localhost:8090}"
ZOVARK_EMAIL="${ZOVARK_EMAIL:-admin@test.local}"
ZOVARK_PASSWORD="${ZOVARK_PASSWORD:-TestPass2026}"
TAIL_LIMIT="${TAIL_LIMIT:-50}"
MODE="watch"    # watch | once
SOURCE="db"     # db | api
TIME_FILTER="1 hour"

# Colors
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
    BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BLUE=''; MAGENTA=''
    BOLD=''; DIM=''; NC=''
fi

# ─── Argument Parsing ───────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)       TIME_FILTER=""; shift ;;
        --watch)     MODE="watch"; shift ;;
        --once)      MODE="once"; shift ;;
        --tail)      TAIL_LIMIT="$2"; shift 2 ;;
        --api)       SOURCE="api"; shift ;;
        --interval)  POLL_INTERVAL="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--all|--watch|--once|--tail N|--api|--interval N]"
            echo ""
            echo "Options:"
            echo "  --all        Show all tasks (not just last hour)"
            echo "  --watch      Continuous refresh every 15s (default)"
            echo "  --once       Single snapshot, then exit"
            echo "  --tail N     Show last N tasks (default: 50)"
            echo "  --api        Use API polling instead of direct DB access"
            echo "  --interval N Refresh interval in seconds (default: 15)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ─── Helpers ─────────────────────────────────────────────────

verdict_color() {
    local verdict="$1"
    case "$verdict" in
        true_positive)  echo "${RED}" ;;
        suspicious)     echo "${YELLOW}" ;;
        benign)         echo "${GREEN}" ;;
        false_positive) echo "${BLUE}" ;;
        inconclusive)   echo "${MAGENTA}" ;;
        *)              echo "${DIM}" ;;
    esac
}

status_color() {
    local status="$1"
    case "$status" in
        completed)  echo "${GREEN}" ;;
        executing)  echo "${YELLOW}" ;;
        pending)    echo "${CYAN}" ;;
        failed)     echo "${RED}" ;;
        *)          echo "${DIM}" ;;
    esac
}

risk_color() {
    local risk="$1"
    if [ -z "$risk" ] || [ "$risk" = "null" ]; then
        echo "${DIM}"
    elif [ "$risk" -ge 70 ]; then
        echo "${RED}"
    elif [ "$risk" -ge 40 ]; then
        echo "${YELLOW}"
    else
        echo "${GREEN}"
    fi
}

# ─── DB Query ────────────────────────────────────────────────

run_db_query() {
    local sql="$1"
    docker exec -e PGPASSWORD="${DB_PASSWORD}" "${DB_CONTAINER}" \
        psql -U "${DB_USER}" -d "${DB_NAME}" -t -A -F '|' -c "$sql" 2>/dev/null
}

check_db() {
    docker exec -e PGPASSWORD="${DB_PASSWORD}" "${DB_CONTAINER}" \
        psql -U "${DB_USER}" -d "${DB_NAME}" -t -A -c "SELECT 1" >/dev/null 2>&1
}

# ─── API Query ───────────────────────────────────────────────

api_token=""

get_api_token() {
    local resp
    resp=$(curl -s -X POST "${ZOVARK_API}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${ZOVARK_EMAIL}\",\"password\":\"${ZOVARK_PASSWORD}\"}" \
        --max-time 10 2>/dev/null)
    api_token=$(echo "$resp" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
}

poll_task_api() {
    local task_id="$1"
    curl -s -H "Authorization: Bearer ${api_token}" \
        "${ZOVARK_API}/api/v1/tasks/${task_id}" \
        --max-time 10 2>/dev/null
}

# ─── Display Functions ───────────────────────────────────────

display_header() {
    local now
    now=$(date "+%Y-%m-%d %H:%M:%S")
    clear 2>/dev/null || true
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}  ZOVARK SIEM Lab — Investigation Monitor${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo -e "  Source:    ${SOURCE}  |  Refresh: ${POLL_INTERVAL}s  |  ${now}"
    echo -e "  Filter:   ${TIME_FILTER:-all time}  |  Limit: ${TAIL_LIMIT}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""
}

display_summary_db() {
    local time_clause=""
    if [ -n "$TIME_FILTER" ]; then
        time_clause="WHERE created_at > NOW() - INTERVAL '${TIME_FILTER}'"
    fi

    # Get status counts
    local counts
    counts=$(run_db_query "
        SELECT status, COUNT(*)
        FROM agent_tasks
        ${time_clause}
        GROUP BY status
        ORDER BY status;
    ")

    local total=0 pending=0 executing=0 completed=0 failed=0
    while IFS='|' read -r status count; do
        [ -z "$status" ] && continue
        case "$status" in
            pending)   pending=$count ;;
            executing) executing=$count ;;
            completed) completed=$count ;;
            failed)    failed=$count ;;
        esac
        total=$((total + count))
    done <<< "$counts"

    echo -e "${BOLD}  Pipeline Status${NC}"
    echo -e "  ────────────────────────────────────────"
    echo -e "  Total:     ${BOLD}${total}${NC}"
    echo -ne "  Pending:   ${CYAN}${pending}${NC}"
    echo -ne "  |  Executing: ${YELLOW}${executing}${NC}"
    echo -ne "  |  Completed: ${GREEN}${completed}${NC}"
    echo -e  "  |  Failed: ${RED}${failed}${NC}"
    echo ""

    # Verdict breakdown for completed tasks
    if [ "$completed" -gt 0 ]; then
        local verdicts
        verdicts=$(run_db_query "
            SELECT
                COALESCE(output->>'verdict', 'unknown') as verdict,
                COUNT(*) as cnt,
                ROUND(AVG(COALESCE((output->>'risk_score')::int, 0))) as avg_risk
            FROM agent_tasks
            ${time_clause}
            ${time_clause:+AND} ${time_clause:+status = 'completed'}
            ${time_clause:-WHERE status = 'completed'}
            GROUP BY output->>'verdict'
            ORDER BY cnt DESC;
        ")

        echo -e "${BOLD}  Verdict Breakdown${NC}"
        echo -e "  ────────────────────────────────────────"
        printf "  %-18s %-8s %-10s\n" "VERDICT" "COUNT" "AVG RISK"

        while IFS='|' read -r verdict cnt avg_risk; do
            [ -z "$verdict" ] && continue
            local vc
            vc=$(verdict_color "$verdict")
            printf "  ${vc}%-18s${NC} %-8s %-10s\n" "$verdict" "$cnt" "$avg_risk"
        done <<< "$verdicts"
        echo ""
    fi

    # Average investigation time
    local avg_time
    avg_time=$(run_db_query "
        SELECT ROUND(AVG(EXTRACT(EPOCH FROM (updated_at - created_at))))
        FROM agent_tasks
        ${time_clause}
        ${time_clause:+AND} ${time_clause:+status = 'completed'}
        ${time_clause:-WHERE status = 'completed'}
        AND updated_at IS NOT NULL;
    " 2>/dev/null | tr -d ' ')

    if [ -n "$avg_time" ] && [ "$avg_time" != "" ]; then
        echo -e "  ${DIM}Avg investigation time: ${avg_time}s${NC}"
        echo ""
    fi
}

display_tasks_db() {
    local time_clause=""
    if [ -n "$TIME_FILTER" ]; then
        time_clause="WHERE t.created_at > NOW() - INTERVAL '${TIME_FILTER}'"
    fi

    local tasks
    tasks=$(run_db_query "
        SELECT
            t.id,
            t.task_type,
            t.status,
            COALESCE(t.output->>'verdict', '-') as verdict,
            COALESCE(t.output->>'risk_score', '-') as risk_score,
            COALESCE(
                ARRAY_LENGTH(
                    ARRAY(SELECT jsonb_array_elements(COALESCE(t.output->'iocs', '[]'::jsonb))),
                    1
                )::text,
                '0'
            ) as ioc_count,
            TO_CHAR(t.created_at, 'HH24:MI:SS') as created,
            CASE
                WHEN t.status = 'completed' AND t.updated_at IS NOT NULL
                THEN ROUND(EXTRACT(EPOCH FROM (t.updated_at - t.created_at)))::text || 's'
                WHEN t.status = 'executing'
                THEN ROUND(EXTRACT(EPOCH FROM (NOW() - t.created_at)))::text || 's...'
                ELSE '-'
            END as duration
        FROM agent_tasks t
        ${time_clause}
        ORDER BY t.created_at DESC
        LIMIT ${TAIL_LIMIT};
    ")

    echo -e "${BOLD}  Recent Investigations${NC}"
    echo -e "  ──────────────────────────────────────────────────────────────────────────────────────"
    printf "  ${DIM}%-8s %-22s %-10s %-15s %-6s %-5s %-8s %-10s${NC}\n" \
        "TIME" "TASK TYPE" "STATUS" "VERDICT" "RISK" "IOCs" "DURATION" "TASK ID"
    echo -e "  ──────────────────────────────────────────────────────────────────────────────────────"

    if [ -z "$tasks" ]; then
        echo -e "  ${DIM}No tasks found in the selected time window.${NC}"
        return
    fi

    while IFS='|' read -r id task_type status verdict risk_score ioc_count created duration; do
        [ -z "$id" ] && continue

        local sc vc rc
        sc=$(status_color "$status")
        vc=$(verdict_color "$verdict")

        # Handle risk color safely
        if [ "$risk_score" = "-" ] || [ "$risk_score" = "null" ] || [ -z "$risk_score" ]; then
            rc="${DIM}"
        else
            rc=$(risk_color "$risk_score")
        fi

        # Truncate task_type for display
        local tt_display="${task_type:0:20}"

        printf "  %-8s %-22s ${sc}%-10s${NC} ${vc}%-15s${NC} ${rc}%-6s${NC} %-5s %-8s ${DIM}%.8s${NC}\n" \
            "$created" "$tt_display" "$status" "$verdict" "$risk_score" "$ioc_count" "$duration" "$id"
    done <<< "$tasks"
    echo ""
}

display_active_investigations() {
    local active
    active=$(run_db_query "
        SELECT
            t.id,
            t.task_type,
            COALESCE(t.input->>'prompt', '-') as prompt,
            TO_CHAR(t.created_at, 'HH24:MI:SS') as created,
            ROUND(EXTRACT(EPOCH FROM (NOW() - t.created_at)))::text as elapsed
        FROM agent_tasks t
        WHERE t.status IN ('pending', 'executing')
        ORDER BY t.created_at ASC
        LIMIT 10;
    ")

    if [ -n "$active" ]; then
        echo -e "${BOLD}  Active Investigations${NC}"
        echo -e "  ────────────────────────────────────────"
        while IFS='|' read -r id task_type prompt created elapsed; do
            [ -z "$id" ] && continue
            echo -e "  ${YELLOW}[ACTIVE]${NC} ${task_type:0:20} (${elapsed}s) ${DIM}${prompt:0:50}${NC}"
        done <<< "$active"
        echo ""
    fi
}

display_recent_iocs() {
    local iocs
    iocs=$(run_db_query "
        SELECT
            ioc_elem->>'type' as ioc_type,
            ioc_elem->>'value' as ioc_value,
            t.task_type,
            COALESCE(t.output->>'verdict', '-') as verdict
        FROM agent_tasks t,
             jsonb_array_elements(COALESCE(t.output->'iocs', '[]'::jsonb)) as ioc_elem
        WHERE t.status = 'completed'
          AND t.output->>'verdict' IN ('true_positive', 'suspicious')
          AND t.created_at > NOW() - INTERVAL '${TIME_FILTER:-24 hours}'
        ORDER BY t.created_at DESC
        LIMIT 15;
    " 2>/dev/null)

    if [ -n "$iocs" ]; then
        echo -e "${BOLD}  Recent IOCs (from true_positive/suspicious verdicts)${NC}"
        echo -e "  ────────────────────────────────────────"
        printf "  ${DIM}%-12s %-40s %-18s %-12s${NC}\n" "TYPE" "VALUE" "TASK TYPE" "VERDICT"

        while IFS='|' read -r ioc_type ioc_value task_type verdict; do
            [ -z "$ioc_type" ] && continue
            local vc
            vc=$(verdict_color "$verdict")
            printf "  %-12s %-40s %-18s ${vc}%-12s${NC}\n" \
                "${ioc_type:0:12}" "${ioc_value:0:40}" "${task_type:0:18}" "$verdict"
        done <<< "$iocs"
        echo ""
    fi
}

display_mitre_techniques() {
    local mitre
    mitre=$(run_db_query "
        SELECT
            technique->>'technique_id' as tid,
            technique->>'technique_name' as tname,
            COUNT(*) as cnt
        FROM agent_tasks t,
             jsonb_array_elements(COALESCE(t.output->'mitre_techniques', '[]'::jsonb)) as technique
        WHERE t.status = 'completed'
          AND t.created_at > NOW() - INTERVAL '${TIME_FILTER:-24 hours}'
        GROUP BY technique->>'technique_id', technique->>'technique_name'
        ORDER BY cnt DESC
        LIMIT 10;
    " 2>/dev/null)

    if [ -n "$mitre" ]; then
        echo -e "${BOLD}  MITRE ATT&CK Techniques Detected${NC}"
        echo -e "  ────────────────────────────────────────"
        printf "  ${DIM}%-12s %-35s %-6s${NC}\n" "TECHNIQUE" "NAME" "COUNT"

        while IFS='|' read -r tid tname cnt; do
            [ -z "$tid" ] && continue
            printf "  ${RED}%-12s${NC} %-35s %-6s\n" "$tid" "${tname:0:35}" "$cnt"
        done <<< "$mitre"
        echo ""
    fi
}

# ─── API-based Display ───────────────────────────────────────

display_via_api() {
    # If we have saved task IDs from the attack script, poll those
    local task_file="/tmp/zovark_siem_lab_tasks.txt"

    if [ ! -f "$task_file" ]; then
        echo -e "${YELLOW}  No task IDs found at ${task_file}${NC}"
        echo -e "${DIM}  Run attack_juice_shop.sh first, or use --db mode (default).${NC}"
        return
    fi

    if [ -z "$api_token" ]; then
        get_api_token
        if [ -z "$api_token" ]; then
            echo -e "${RED}  Failed to authenticate with API${NC}"
            return
        fi
    fi

    local total=0 completed=0 pending=0 failed=0

    echo -e "${BOLD}  Task Results (via API)${NC}"
    echo -e "  ──────────────────────────────────────────────────────────────────────────────────────"
    printf "  ${DIM}%-38s %-10s %-15s %-6s %-5s${NC}\n" \
        "TASK ID" "STATUS" "VERDICT" "RISK" "IOCs"
    echo -e "  ──────────────────────────────────────────────────────────────────────────────────────"

    while IFS= read -r task_id; do
        [ -z "$task_id" ] && continue
        total=$((total + 1))

        local resp
        resp=$(poll_task_api "$task_id")

        local status verdict risk_score ioc_count
        status=$(echo "$resp" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
        verdict=$(echo "$resp" | grep -o '"verdict":"[^"]*"' | head -1 | cut -d'"' -f4)
        risk_score=$(echo "$resp" | grep -o '"risk_score":[0-9]*' | head -1 | cut -d: -f2)

        status="${status:-unknown}"
        verdict="${verdict:--}"
        risk_score="${risk_score:--}"

        case "$status" in
            completed) completed=$((completed + 1)) ;;
            pending|executing) pending=$((pending + 1)) ;;
            failed) failed=$((failed + 1)) ;;
        esac

        local sc vc
        sc=$(status_color "$status")
        vc=$(verdict_color "$verdict")

        printf "  %-38s ${sc}%-10s${NC} ${vc}%-15s${NC} %-6s\n" \
            "$task_id" "$status" "$verdict" "$risk_score"

    done < "$task_file"

    echo ""
    echo -e "  Total: ${total}  |  ${GREEN}Completed: ${completed}${NC}  |  ${CYAN}Pending: ${pending}${NC}  |  ${RED}Failed: ${failed}${NC}"
    echo ""
}

# ─── Main Display Loop ──────────────────────────────────────

render() {
    display_header

    if [ "$SOURCE" = "api" ]; then
        display_via_api
    else
        display_summary_db
        display_active_investigations
        display_tasks_db
        display_recent_iocs
        display_mitre_techniques
    fi

    if [ "$MODE" = "watch" ]; then
        echo -e "${DIM}  Refreshing in ${POLL_INTERVAL}s... (Ctrl+C to exit)${NC}"
    fi
}

main() {
    # Verify connectivity
    if [ "$SOURCE" = "db" ]; then
        echo "Checking database connectivity..."
        if ! check_db; then
            echo "ERROR: Cannot connect to PostgreSQL container '${DB_CONTAINER}'."
            echo "  Make sure services are running:  docker compose up -d"
            echo "  Or use API mode:  $0 --api"
            exit 1
        fi
        echo "Database connected."
    else
        echo "Using API polling mode."
        get_api_token
        if [ -z "$api_token" ]; then
            echo "ERROR: Cannot authenticate with Zovark API at ${ZOVARK_API}"
            exit 1
        fi
        echo "API authenticated."
    fi

    if [ "$MODE" = "once" ]; then
        render
    else
        # Continuous watch mode
        trap 'echo ""; echo "Monitor stopped."; exit 0' INT TERM
        while true; do
            render
            sleep "$POLL_INTERVAL"
            # Refresh API token periodically (every ~5 minutes)
            if [ "$SOURCE" = "api" ]; then
                get_api_token 2>/dev/null || true
            fi
        done
    fi
}

main
