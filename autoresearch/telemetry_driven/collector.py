"""Telemetry collector — queries PostgreSQL, Redis, and OOB for system state."""

import json
import os
import time


class PostgresCollector:
    """Collects investigation telemetry via psycopg2 (runs inside worker container)."""

    def __init__(self):
        self.db_url = os.environ.get(
            "DATABASE_URL",
            "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark"
        )

    def _query(self, sql):
        import psycopg2
        rows = []
        try:
            conn = psycopg2.connect(self.db_url)
            with conn.cursor() as cur:
                cur.execute(sql)
                rows = [list(r) for r in cur.fetchall()]
            conn.close()
        except Exception as e:
            print(f"  [pg] query error: {e}")
        return rows

    def risk_score_distribution(self, hours=24):
        return self._query(f"""
            SELECT task_type, COUNT(*)::text,
                   ROUND(AVG((output->>'risk_score')::numeric),1)::text,
                   ROUND(COALESCE(STDDEV((output->>'risk_score')::numeric),0),1)::text,
                   MIN((output->>'risk_score')::int)::text,
                   MAX((output->>'risk_score')::int)::text
            FROM agent_tasks
            WHERE status='completed' AND output->>'risk_score' IS NOT NULL
              AND created_at > NOW() - INTERVAL '{hours} hours'
            GROUP BY task_type ORDER BY 3 ASC
        """)

    def verdict_distribution(self, hours=24):
        return self._query(f"""
            SELECT task_type, output->>'verdict', COUNT(*)::text
            FROM agent_tasks
            WHERE status='completed' AND output->>'verdict' IS NOT NULL
              AND created_at > NOW() - INTERVAL '{hours} hours'
            GROUP BY task_type, output->>'verdict' ORDER BY 1, 3 DESC
        """)

    def error_rate(self, hours=24):
        return self._query(f"""
            SELECT task_type,
                   COUNT(*) FILTER (WHERE status IN ('error','failed'))::text,
                   COUNT(*) FILTER (WHERE output->>'verdict'='needs_manual_review')::text,
                   COUNT(*)::text,
                   ROUND(100.0 * COUNT(*) FILTER (WHERE status IN ('error','failed')) / GREATEST(COUNT(*),1), 1)::text
            FROM agent_tasks WHERE created_at > NOW() - INTERVAL '{hours} hours'
            GROUP BY task_type HAVING COUNT(*) >= 2 ORDER BY 5 DESC
        """)

    def dedup_hotspots(self, hours=24):
        return self._query(f"""
            SELECT task_type, SUM(COALESCE(dedup_count,0))::text,
                   COUNT(*)::text,
                   ROUND(SUM(COALESCE(dedup_count,0))::numeric / GREATEST(COUNT(*),1), 1)::text
            FROM agent_tasks
            WHERE created_at > NOW() - INTERVAL '{hours} hours' AND COALESCE(dedup_count,0) > 0
            GROUP BY task_type ORDER BY 4 DESC
        """)

    def latency_by_path(self, hours=24):
        return self._query(f"""
            SELECT COALESCE(path_taken, 'unknown'), COUNT(*)::text,
                   ROUND(AVG(EXTRACT(EPOCH FROM (completed_at - created_at)))::numeric, 2)::text,
                   ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - created_at)))::numeric, 2)::text,
                   ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - created_at)))::numeric, 2)::text,
                   MAX(EXTRACT(EPOCH FROM (completed_at - created_at)))::int::text
            FROM agent_tasks
            WHERE status='completed' AND completed_at IS NOT NULL
              AND created_at > NOW() - INTERVAL '{hours} hours'
            GROUP BY path_taken ORDER BY 3 DESC
        """)

    def mitre_coverage(self, hours=24):
        return self._query(f"""
            SELECT task_type, COUNT(*)::text,
                   COUNT(*) FILTER (WHERE output->'mitre_attack' IS NOT NULL
                       AND jsonb_array_length(COALESCE(output->'mitre_attack','[]'::jsonb)) > 0)::text,
                   ROUND(100.0 * COUNT(*) FILTER (WHERE output->'mitre_attack' IS NOT NULL
                       AND jsonb_array_length(COALESCE(output->'mitre_attack','[]'::jsonb)) > 0)
                       / GREATEST(COUNT(*),1), 0)::text
            FROM agent_tasks
            WHERE status='completed' AND output->>'verdict' IN ('true_positive','suspicious')
              AND created_at > NOW() - INTERVAL '{hours} hours'
            GROUP BY task_type ORDER BY 4 ASC
        """)

    def recent_failures(self, limit=20):
        return self._query(f"""
            SELECT id::text, task_type, status,
                   COALESCE(output->>'verdict',''),
                   COALESCE((output->>'risk_score')::int, 0)::text,
                   created_at::text
            FROM agent_tasks
            WHERE status IN ('error','failed') OR output->>'verdict'='needs_manual_review'
            ORDER BY created_at DESC LIMIT {limit}
        """)


class RedisCollector:
    """Collects dedup/burst stats from Valkey via redis-py."""

    def __init__(self):
        redis_url = os.environ.get("REDIS_URL", "redis://:zovark_valkey_dev_2026@redis:6379/0")
        try:
            import redis
            self.r = redis.from_url(redis_url, decode_responses=True)
            self.r.ping()
        except Exception:
            self.r = None

    def dedup_stats(self):
        stats = {}
        if not self.r:
            return stats
        for d in ["new_alert", "deduplicated", "severity_escalation", "retry_after_failure"]:
            val = self.r.get(f"dedup:stats:{d}")
            stats[d] = int(val) if val else 0
        total = sum(stats.values())
        stats["total"] = total
        if total > 0:
            stats["dedup_ratio_pct"] = round(100 * stats["deduplicated"] / total, 1)
        return stats

    def backpressure_depth(self):
        if not self.r:
            return 0
        val = self.r.zcard("zovark:pending_workflows")
        return val or 0


class OOBCollector:
    def state(self):
        import requests
        try:
            # From inside Docker network, OOB is on the api container
            # Try host first, then Docker service name
            for url in ["http://host.docker.internal:9091/debug/state",
                        "http://zovark-api:9091/debug/state"]:
                try:
                    return requests.get(url, timeout=3).json()
                except Exception:
                    continue
            return {"error": "OOB unreachable from container"}
        except Exception:
            return {"error": "OOB unreachable"}


class TelemetrySnapshot:
    def __init__(self):
        self.pg = PostgresCollector()
        self.redis = RedisCollector()
        self.oob = OOBCollector()

    def collect(self, hours=24):
        snapshot = {
            "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "window_hours": hours,
            "sources": {},
            "data": {}
        }
        try:
            snapshot["data"]["risk_scores"] = self.pg.risk_score_distribution(hours)
            snapshot["data"]["verdicts"] = self.pg.verdict_distribution(hours)
            snapshot["data"]["error_rates"] = self.pg.error_rate(hours)
            snapshot["data"]["dedup_hotspots"] = self.pg.dedup_hotspots(hours)
            snapshot["data"]["latency"] = self.pg.latency_by_path(hours)
            snapshot["data"]["mitre_coverage"] = self.pg.mitre_coverage(hours)
            snapshot["data"]["recent_failures"] = self.pg.recent_failures()
            snapshot["sources"]["postgres"] = "ok"
        except Exception as e:
            snapshot["sources"]["postgres"] = f"error: {e}"
        try:
            snapshot["data"]["dedup_stats"] = self.redis.dedup_stats()
            snapshot["data"]["backpressure_depth"] = self.redis.backpressure_depth()
            snapshot["sources"]["redis"] = "ok"
        except Exception as e:
            snapshot["sources"]["redis"] = f"error: {e}"
        try:
            snapshot["data"]["system_health"] = self.oob.state()
            snapshot["sources"]["oob"] = "ok"
        except Exception as e:
            snapshot["sources"]["oob"] = f"error: {e}"
        return snapshot

    def save(self, snapshot, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(snapshot, f, indent=2, default=str)


if __name__ == "__main__":
    snap = TelemetrySnapshot()
    result = snap.collect(hours=168)
    print(f"Sources: {result['sources']}")
    d = result["data"]
    print(f"Risk scores: {len(d.get('risk_scores', []))} task types")
    print(f"Verdicts: {len(d.get('verdicts', []))} entries")
    print(f"Dedup stats: {d.get('dedup_stats', {})}")
    print(f"Latency: {len(d.get('latency', []))} paths")
    print(f"Failures: {len(d.get('recent_failures', []))}")
    snap.save(result, "results/snapshot_test.json")
    print("Saved.")
