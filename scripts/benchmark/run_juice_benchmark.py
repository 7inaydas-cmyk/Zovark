#!/usr/bin/env python3
"""
ZOVARK Juice Shop Benchmark Runner — submits real-traffic corpus to ZOVARK pipeline.

Usage:
    python scripts/benchmark/run_juice_benchmark.py
    python scripts/benchmark/run_juice_benchmark.py --limit 10
    python scripts/benchmark/run_juice_benchmark.py --spacing 15
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from collections import defaultdict

API_URL = os.environ.get("ZOVARK_API_URL", "http://localhost:8090")
CORPUS_PATH = Path(__file__).parent / "juice_shop_corpus.json"
RESULTS_PATH = Path(__file__).parent / "juice_shop_results.json"
REPORT_PATH = Path("docs/JUICE_SHOP_BENCHMARK.md")


def login(api_url):
    email = os.environ.get("ZOVARK_TEST_EMAIL", "admin@test.local")
    password = os.environ.get("ZOVARK_TEST_PASSWORD", "TestPass2026")
    payload = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(f"{api_url}/api/v1/auth/login", data=payload,
                                 headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())["token"]


# --- JWT auto-refresh state ---
_token_state = {"token": None, "api_url": None, "submit_count": 0}


def get_fresh_token(api_url, force=False):
    """Get a valid JWT token, refreshing every 10 submissions or on demand.

    Auto-refreshes to avoid 15-minute JWT expiry during long benchmarks.
    """
    _token_state["api_url"] = api_url
    _token_state["submit_count"] += 1

    if force or _token_state["token"] is None or _token_state["submit_count"] % 10 == 0:
        try:
            _token_state["token"] = login(api_url)
            if force:
                print("  [Token refreshed after 401]")
        except Exception as e:
            print(f"  Warning: Token refresh failed: {e}")
            # Keep using old token if refresh fails
            if _token_state["token"] is None:
                raise

    return _token_state["token"]


def flush_redis():
    import subprocess
    try:
        redis_pw = os.environ.get("REDIS_PASSWORD", "zovark-redis-dev-2026")
        subprocess.run(["docker", "compose", "exec", "-T", "redis", "valkey-cli", "-a", redis_pw, "FLUSHDB"],
                      capture_output=True, timeout=10)
    except Exception:
        print("  Warning: Could not flush Redis cache")


def submit_alert(api_url, token, alert):
    payload = json.dumps({
        "task_type": alert["task_type"],
        "input": {
            "prompt": alert.get("prompt", f"Investigate {alert['task_type']}"),
            "severity": alert.get("severity", "high"),
            "siem_event": alert["siem_event"],
        }
    }).encode()
    for attempt in range(2):
        try:
            req = urllib.request.Request(f"{api_url}/api/v1/tasks", data=payload,
                                         headers={"Authorization": f"Bearer {token}",
                                                   "Content-Type": "application/json"})
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 401 and attempt == 0:
                token = get_fresh_token(api_url, force=True)
                continue
            raise


def poll_task(api_url, token, task_id, timeout_s=300):
    start = time.time()
    while time.time() - start < timeout_s:
        try:
            req = urllib.request.Request(f"{api_url}/api/v1/tasks/{task_id}",
                                         headers={"Authorization": f"Bearer {token}"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            status = data.get("status", "unknown")
            if status not in ("pending", "executing"):
                return data
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Auto-refresh token on 401 during polling
                token = get_fresh_token(api_url, force=True)
                continue
        except Exception:
            pass
        time.sleep(15)
    return {"status": "timeout"}


def generate_report(results, corpus_size):
    """Generate markdown benchmark report."""
    completed = [r for r in results if r["status"] == "completed"]

    # Verdict scoring
    correct = 0
    total_scored = 0
    tp_detected = 0
    tp_total = 0
    fp_detected = 0
    fp_total = 0
    benign_detected = 0
    benign_total = 0

    # Confusion matrix: actual x predicted
    confusion = defaultdict(lambda: defaultdict(int))
    by_attack_type = defaultdict(lambda: {"correct": 0, "total": 0, "times": []})

    for r in completed:
        gt = r.get("ground_truth", {})
        expected = gt.get("verdict", "unknown")
        actual = r.get("actual_verdict", "unknown")
        attack_type = gt.get("attack_type", "benign") or "benign"

        total_scored += 1
        confusion[expected][actual] += 1
        by_attack_type[attack_type]["total"] += 1
        by_attack_type[attack_type]["times"].append(r.get("duration", 0))

        if actual == expected:
            correct += 1
            by_attack_type[attack_type]["correct"] += 1

        if expected == "true_positive":
            tp_total += 1
            if actual == "true_positive":
                tp_detected += 1
        elif expected in ("false_positive", "benign"):
            if expected == "false_positive":
                fp_total += 1
                if actual in ("false_positive", "benign"):
                    fp_detected += 1
            else:
                benign_total += 1
                if actual in ("benign", "false_positive"):
                    benign_detected += 1

    accuracy = correct / total_scored * 100 if total_scored else 0
    tp_rate = tp_detected / tp_total * 100 if tp_total else 0
    fp_rate = fp_detected / fp_total * 100 if fp_total else 0

    times = [r["duration"] for r in completed if "duration" in r]
    avg_time = sum(times) / len(times) if times else 0

    n_failed = sum(1 for r in results if r["status"] == "failed")
    n_timeout = sum(1 for r in results if r["status"] == "timeout")
    n_error = sum(1 for r in results if r["status"] == "error")

    report = f"""# ZOVARK Accuracy Benchmark: OWASP Juice Shop
## Real-Traffic Test (not synthetic)

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}

> This benchmark uses **real attack traffic** against OWASP Juice Shop,
> not synthetic SIEM events. Accuracy numbers are more representative
> of production performance.

### Overall

| Metric | Value |
|--------|-------|
| Total alerts | {corpus_size} |
| Completed | {len(completed)}/{corpus_size} |
| Failed | {n_failed} |
| Timeout | {n_timeout} |
| Error | {n_error} |
| **Overall accuracy** | **{accuracy:.1f}%** |
| True positive detection | {tp_rate:.0f}% ({tp_detected}/{tp_total}) |
| False positive identification | {fp_rate:.0f}% ({fp_detected}/{fp_total}) |
| Mean investigation time | {avg_time:.0f}s |

### Per Attack Type

| Attack Type | Count | Accuracy | Avg Time |
|------------|-------|----------|----------|
"""
    for attack_type in sorted(by_attack_type.keys()):
        bt = by_attack_type[attack_type]
        acc = bt["correct"] / bt["total"] * 100 if bt["total"] else 0
        avg_t = sum(bt["times"]) / len(bt["times"]) if bt["times"] else 0
        report += f"| {attack_type} | {bt['total']} | {acc:.0f}% | {avg_t:.0f}s |\n"

    verdicts = ["true_positive", "false_positive", "suspicious", "benign", "inconclusive"]
    report += """
### Confusion Matrix

| Actual \\ Predicted | true_positive | false_positive | suspicious | benign | inconclusive |
|---------------------|:---:|:---:|:---:|:---:|:---:|
"""
    for actual in ["true_positive", "false_positive", "benign"]:
        row = [str(confusion[actual].get(v, 0)) for v in verdicts]
        report += f"| {actual} | {' | '.join(row)} |\n"

    report += """
### Methodology

- **Target:** OWASP Juice Shop v17 (Docker)
- **Attack types:** SQL injection, XSS, path traversal, broken auth, IDOR, SSRF, file upload, command injection
- **Benign traffic:** Normal logins, product searches, API calls
- **Pipeline:** ZOVARK V2 (Ingest -> Analyze -> Execute -> Assess -> Store)
- **Scoring:** Exact match on verdict category (TP detection counts suspicious as partial credit)

> NOTE: This benchmark uses REAL attack traffic against OWASP Juice Shop,
> not synthetic SIEM events.
"""
    return report


def main():
    parser = argparse.ArgumentParser(description="ZOVARK Juice Shop Benchmark")
    parser.add_argument("--limit", type=int, default=0, help="Max alerts (0=all)")
    parser.add_argument("--spacing", type=int, default=30, help="Seconds between submissions")
    parser.add_argument("--timeout", type=int, default=300, help="Max seconds per alert")
    parser.add_argument("--api-url", default=API_URL)
    parser.add_argument("--corpus", default=str(CORPUS_PATH))
    args = parser.parse_args()

    with open(args.corpus) as f:
        raw = json.load(f)
    # Support both flat list and wrapped {"alerts": [...]} format
    corpus = raw.get("alerts", raw) if isinstance(raw, dict) else raw

    if args.limit > 0:
        corpus = corpus[:args.limit]

    print(f"ZOVARK Juice Shop Benchmark")
    print(f"  Corpus:  {len(corpus)} alerts")
    print(f"  Spacing: {args.spacing}s")
    print()

    # Flush dedup cache
    print("Flushing Redis dedup cache...")
    flush_redis()

    token = get_fresh_token(args.api_url)
    print("Authenticated.\n")

    results = []
    for idx, alert in enumerate(corpus):
        task_type = alert["task_type"]
        gt = alert.get("ground_truth", {})
        gt_verdict = gt.get("verdict", "?")
        attack_type = gt.get("attack_type", "benign") or "benign"

        print(f"[{idx+1}/{len(corpus)}] {attack_type:20s} (expect: {gt_verdict})...", end=" ", flush=True)

        # Auto-refresh token every 10 submissions (JWT expires every 15 min)
        token = get_fresh_token(args.api_url)

        t0 = time.time()
        try:
            resp = submit_alert(args.api_url, token, alert)
            task_id = resp.get("task_id", "")

            if resp.get("status") == "deduplicated":
                elapsed = time.time() - t0
                print(f"DEDUP ({elapsed:.0f}s)")
                results.append({"idx": idx, "task_type": task_type, "status": "deduplicated",
                               "duration": elapsed, "ground_truth": gt})
                continue

            data = poll_task(args.api_url, token, task_id, args.timeout)
            elapsed = time.time() - t0
            status = data.get("status", "timeout")
            output = data.get("output", {}) or {}

            actual_verdict = output.get("verdict", "unknown")
            is_correct = actual_verdict == gt_verdict

            print(f"{status.upper()} ({elapsed:.0f}s) verdict={actual_verdict} {'OK' if is_correct else 'WRONG'}")

            results.append({
                "idx": idx, "task_type": task_type, "task_id": task_id,
                "status": status, "duration": elapsed,
                "ground_truth": gt,
                "actual_verdict": actual_verdict,
                "actual_risk_score": output.get("risk_score", 0),
                "actual_iocs": [ioc.get("value", str(ioc)) if isinstance(ioc, dict) else str(ioc)
                               for ioc in output.get("iocs", [])],
                "model_used": output.get("model_used", "unknown"),
            })

        except Exception as e:
            elapsed = time.time() - t0
            print(f"ERROR ({elapsed:.0f}s): {e}")
            results.append({"idx": idx, "task_type": task_type, "status": "error",
                           "duration": elapsed, "error": str(e), "ground_truth": gt})

        if idx < len(corpus) - 1:
            time.sleep(args.spacing)

    # Save results
    with open(RESULTS_PATH, "w") as f:
        json.dump({"timestamp": datetime.now().isoformat(), "results": results}, f, indent=2)
    print(f"\nResults saved to {RESULTS_PATH}")

    # Generate report
    report = generate_report(results, len(corpus))
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        f.write(report)
    print(f"Report saved to {REPORT_PATH}")

    # Quick summary
    completed = [r for r in results if r["status"] == "completed"]
    correct = sum(1 for r in completed
                  if r.get("actual_verdict") == r.get("ground_truth", {}).get("verdict"))
    print(f"\nCompleted: {len(completed)}/{len(corpus)}")
    print(f"Correct: {correct}/{len(completed)} ({100*correct/len(completed) if completed else 0:.0f}%)")


if __name__ == "__main__":
    main()
