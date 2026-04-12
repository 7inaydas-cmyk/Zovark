#!/usr/bin/env python3
"""
ZOVARK Model Benchmark — run labeled corpus against a specific model endpoint.

Usage:
    python scripts/model_benchmark.py --model-url http://localhost:11434/v1/chat/completions --model-name qwen25-14b --corpus scripts/benchmark_corpus_11.json --api-url http://localhost:8090
    python scripts/model_benchmark.py --help
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
import urllib.request

API_URL = os.environ.get("ZOVARK_API_URL", "http://localhost:8090")


def login(api_url: str) -> str:
    email = os.environ.get("ZOVARK_TEST_EMAIL", "admin@test.local")
    password = os.environ.get("ZOVARK_TEST_PASSWORD", "TestPass2026")
    payload = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(f"{api_url}/api/v1/auth/login", data=payload,
                                 headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())["token"]


def flush_redis():
    """Flush Redis dedup cache via docker compose."""
    import subprocess
    try:
        redis_pw = os.environ.get("REDIS_PASSWORD", "zovark-redis-dev-2026")
        subprocess.run(
            ["docker", "compose", "exec", "-T", "redis", "valkey-cli", "-a", redis_pw, "FLUSHDB"],
            capture_output=True, timeout=10
        )
    except Exception:
        print("  Warning: Could not flush Redis cache")


def submit_alert(api_url: str, token: str, alert: dict) -> dict:
    payload = json.dumps({
        "task_type": alert["task_type"],
        "input": {
            "prompt": f"Investigate {alert['task_type'].replace('_', ' ')}",
            "severity": alert.get("severity", "high"),
            "siem_event": alert["siem_event"],
        }
    }).encode()
    req = urllib.request.Request(f"{api_url}/api/v1/tasks", data=payload,
                                 headers={"Authorization": f"Bearer {token}",
                                           "Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=30)
    return json.loads(resp.read())


def poll_task(api_url: str, token: str, task_id: str, timeout_s: int = 300) -> dict:
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
        except Exception:
            pass
        time.sleep(15)
    return {"status": "timeout"}


def score_result(result: dict, ground_truth: dict) -> dict:
    """Score a single investigation against ground truth."""
    output = result.get("output", {}) or {}

    # Verdict accuracy
    actual_verdict = output.get("verdict", "unknown")
    expected_verdict = ground_truth.get("verdict", "unknown")
    verdict_correct = actual_verdict == expected_verdict

    # IOC recall
    expected_iocs = set(ground_truth.get("expected_iocs", []))
    found_iocs = set()
    for ioc in output.get("iocs", []):
        if isinstance(ioc, dict):
            found_iocs.add(ioc.get("value", ""))
        elif isinstance(ioc, str):
            found_iocs.add(ioc)

    ioc_matches = expected_iocs & found_iocs
    ioc_recall = len(ioc_matches) / len(expected_iocs) if expected_iocs else 1.0
    ioc_precision = len(ioc_matches) / len(found_iocs) if found_iocs else 0.0

    # Risk score
    risk_score = output.get("risk_score", 0)
    risk_range = ground_truth.get("expected_risk_range", [0, 100])
    risk_in_range = risk_range[0] <= risk_score <= risk_range[1]

    # Code
    code = ""
    if isinstance(output, dict):
        code = output.get("code", "")[:200]

    return {
        "verdict_correct": verdict_correct,
        "actual_verdict": actual_verdict,
        "expected_verdict": expected_verdict,
        "ioc_recall": ioc_recall,
        "ioc_precision": ioc_precision,
        "iocs_found": list(found_iocs),
        "iocs_expected": list(expected_iocs),
        "risk_score": risk_score,
        "risk_in_range": risk_in_range,
        "code_generated": code,
        "summary": output.get("summary", output.get("memory_summary", "")),
    }


def main():
    parser = argparse.ArgumentParser(description="ZOVARK Model Benchmark Runner")
    parser.add_argument("--model-url", required=True, help="LLM endpoint URL")
    parser.add_argument("--model-name", required=True, help="Model label for results")
    parser.add_argument("--corpus", required=True, help="Path to benchmark corpus JSON")
    parser.add_argument("--api-url", default=API_URL, help="ZOVARK API URL")
    parser.add_argument("--timeout", type=int, default=300, help="Max seconds per investigation")
    parser.add_argument("--no-flush", action="store_true", help="Don't flush Redis cache")
    args = parser.parse_args()

    # Load corpus
    with open(args.corpus) as f:
        corpus = json.load(f)

    print(f"ZOVARK Model Benchmark")
    print(f"  Model:   {args.model_name}")
    print(f"  URL:     {args.model_url}")
    print(f"  Corpus:  {len(corpus)} alerts")
    print(f"  API:     {args.api_url}")
    print()

    # Flush cache
    if not args.no_flush:
        print("Flushing Redis dedup cache...")
        flush_redis()

    # Auth
    token = login(args.api_url)
    print("Authenticated.\n")

    results = []
    for idx, alert in enumerate(corpus):
        task_type = alert["task_type"]
        print(f"[{idx+1}/{len(corpus)}] {task_type}...", end=" ", flush=True)

        t0 = time.time()
        try:
            resp = submit_alert(args.api_url, token, alert)
            task_id = resp.get("task_id", "")

            if resp.get("status") == "deduplicated":
                elapsed = time.time() - t0
                print(f"DEDUP ({elapsed:.0f}s)")
                results.append({
                    "idx": idx, "task_type": task_type, "task_id": task_id,
                    "status": "deduplicated", "duration": elapsed,
                })
                continue

            data = poll_task(args.api_url, token, task_id, args.timeout)
            elapsed = time.time() - t0
            status = data.get("status", "timeout")

            score = {}
            if status == "completed" and "ground_truth" in alert:
                score = score_result(data, alert["ground_truth"])

            print(f"{status.upper()} ({elapsed:.0f}s)" +
                  (f" verdict={'correct' if score.get('verdict_correct') else 'wrong'}" if score else ""))

            results.append({
                "idx": idx, "task_type": task_type, "task_id": task_id,
                "status": status, "duration": elapsed, **score,
            })

        except Exception as e:
            elapsed = time.time() - t0
            print(f"ERROR ({elapsed:.0f}s): {e}")
            results.append({
                "idx": idx, "task_type": task_type, "task_id": "",
                "status": "error", "duration": elapsed, "error": str(e),
            })

        # Refresh token every 3 alerts
        if (idx + 1) % 3 == 0:
            try:
                token = login(args.api_url)
            except Exception:
                pass

    # Summary
    completed = [r for r in results if r["status"] == "completed"]
    correct_verdicts = sum(1 for r in completed if r.get("verdict_correct"))
    avg_time = sum(r["duration"] for r in completed) / len(completed) if completed else 0
    median_time = sorted(r["duration"] for r in completed)[len(completed)//2] if completed else 0
    avg_ioc_recall = sum(r.get("ioc_recall", 0) for r in completed) / len(completed) if completed else 0

    print(f"\n{'='*60}")
    print(f"Model: {args.model_name}")
    print(f"{'='*60}")
    print(f"{'Metric':<20} {'Value':>10}")
    print(f"{'-'*30}")
    print(f"{'Completed':<20} {len(completed):>10}/{len(corpus)}")
    print(f"{'Accuracy':<20} {correct_verdicts:>10}/{len(completed)} ({100*correct_verdicts/len(completed) if completed else 0:.0f}%)")
    print(f"{'IOC Recall':<20} {100*avg_ioc_recall:>9.0f}%")
    print(f"{'Avg Time':<20} {avg_time:>9.0f}s")
    print(f"{'Median Time':<20} {median_time:>9.0f}s")
    print(f"{'='*60}")

    # Save results
    output_file = f"benchmark_results_{args.model_name}.json"
    with open(output_file, "w") as f:
        json.dump({
            "model_name": args.model_name,
            "model_url": args.model_url,
            "timestamp": datetime.now().isoformat(),
            "corpus_size": len(corpus),
            "completed": len(completed),
            "accuracy": correct_verdicts / len(completed) if completed else 0,
            "avg_ioc_recall": avg_ioc_recall,
            "avg_time": avg_time,
            "median_time": median_time,
            "results": results,
        }, f, indent=2)
    print(f"\nSaved: {output_file}")


if __name__ == "__main__":
    main()
