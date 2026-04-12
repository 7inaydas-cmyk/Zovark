"""Shared fixtures for integration tests."""
import os
import sys
import time
import pytest
import subprocess
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))

API_URL = os.getenv("ZOVARK_TEST_API", "http://localhost:8090")
TEST_EMAIL = os.getenv("ZOVARK_TEST_EMAIL", "admin@test.local")
TEST_PASSWORD = os.getenv("ZOVARK_TEST_PASSWORD", "TestPass2026")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "hydra-redis-dev-2026")


@pytest.fixture(scope="session")
def api_token():
    import urllib.request
    try:
        data = json.dumps({"email": TEST_EMAIL, "password": TEST_PASSWORD}).encode()
        req = urllib.request.Request(
            f"{API_URL}/api/v1/auth/login",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            token = json.loads(resp.read()).get("token", "")
            assert token, "Empty token returned"
            return token
    except Exception as e:
        pytest.skip(f"Zovark API not available: {e}")


@pytest.fixture(autouse=True)
def flush_dedup():
    try:
        subprocess.run(
            ["docker", "compose", "exec", "-T", "redis", "valkey-cli",
             "-a", REDIS_PASSWORD, "--no-auth-warning",
             "EVAL", "local keys = redis.call('keys', 'dedup:*'); for _,k in ipairs(keys) do redis.call('del', k) end; return #keys", "0"],
            capture_output=True, text=True, timeout=5
        )
    except Exception:
        pass
    yield


def submit_task(token: str, task_type: str, siem_event: dict,
                severity: str = "high", timeout: int = 120) -> dict:
    import urllib.request
    payload = json.dumps({
        "task_type": task_type,
        "input": {
            "prompt": siem_event.get("title", task_type),
            "severity": severity,
            "siem_event": siem_event,
        }
    }).encode()

    req = urllib.request.Request(
        f"{API_URL}/api/v1/tasks",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        task_result = json.loads(resp.read())

    task_id = task_result.get("id", task_result.get("task_id", ""))

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(2)
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "postgres", "psql",
             "-U", "zovark", "-d", "zovark", "-t", "-c",
             f"SELECT status, output::text FROM agent_tasks WHERE id='{task_id}' OR "
             f"(task_type='{task_type}' AND created_at > NOW()-INTERVAL '2 min') "
             f"ORDER BY created_at DESC LIMIT 1;"],
            capture_output=True, text=True, timeout=10
        )

        if result.stdout:
            parts = result.stdout.strip().split("|", 1)
            status = parts[0].strip() if parts else ""
            if status in ("completed", "failed"):
                output_str = parts[1].strip() if len(parts) > 1 else "{}"
                try:
                    return json.loads(output_str)
                except json.JSONDecodeError:
                    return {"status": status, "raw": output_str}

    pytest.fail(f"Task {task_type} did not complete within {timeout}s")
