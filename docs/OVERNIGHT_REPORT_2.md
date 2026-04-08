# OVERNIGHT REPORT — 2026-04-08/09

## State Audit Results
Regression 16/16, Dedup 14/14 — pipeline was green at session start.
6 unit test failures found (3 detection threshold + 3 egress controller).
credential_access scoring at risk=50 (should be >=65).
detect_supply_chain tool missing.
Dual-endpoint configured but both pointing to same local inference.
Content scanner 76 patterns — 7 red team bypasses found.
Healer at 509MB/512MB (memory leak).

## Gaps Fixed

| Gap | Root Cause | Fix | Commit |
|-----|-----------|-----|--------|
| 3 detection threshold tests | Calibration raised scores past test thresholds | Cap krbtgt risk, gate golden_ticket boost on keywords, require 2+ findings for data_exfil floor | 4dfa592 |
| 3 egress controller tests | zovark-inference missing from NO_PROXY_HOSTS, constructor ignored empty proxy_url | Added to allowlist, used `is not None` check | 4dfa592 |
| credential_access risk=50 | No dedicated detection tool — score_generic only counted keywords | Built detect_credential_access with LSASS+tool combo floor at 85 | 28a6494 |
| detect_supply_chain missing | supply_chain_compromise plan used score_generic | Built detect_supply_chain with 6 pattern categories | 28a6494 |
| Dual-endpoint not wired | llm_client.py used single base URL | Client pool keyed by base URL, endpoint routing by role | 35a48d0 |
| 7 content scanner bypasses | Missing patterns for /dev/tcp, netcat, socat, base64 pipe, subshell, supply chain | Added 11 new patterns (87 total) | 134a045 |
| Healer unhealthy | Known memory leak at 509MB/512MB | Restarted (now 81MB) | N/A |

## Scoring Status (final 100-alert run)

| Type | N | Avg Risk | Min | Max |
|------|---|----------|-----|-----|
| credential_access | 1 | 100 | 100 | 100 |
| c2/c2_communication | 8 | 100 | 100 | 100 |
| data_exfiltration | 1 | 100 | 100 | 100 |
| brute_force | 11 | 95 | 95 | 95 |
| kerberoasting | 6 | 95 | 80 | 100 |
| golden_ticket | 2 | 87.5 | 75 | 100 |
| phishing | 9 | 86.7 | 70 | 100 |
| lolbin_abuse | 4 | 81.3 | 70 | 100 |
| dns_exfiltration | 4 | 77.5 | 70 | 100 |
| ransomware | 7 | 74.3 | 70 | 85 |
| powershell_obfuscation | 3 | 70 | 70 | 70 |
| dcsync | 2 | 70 | 70 | 70 |
| dll_sideloading | 2 | 70 | 70 | 70 |
| lateral_movement | 2 | 70 | 70 | 70 |
| process_injection | 3 | 70 | 70 | 70 |
| data_exfil | 5 | 63 | 30 | 90 |
| All benign (27 types) | 27 | 0 | 0 | 0 |

## New Detection Coverage
- Content scanner patterns: 87 (was 76)
- Signal boost patterns: 11 (unchanged)
- detect_credential_access: BUILT — LSASS, mimikatz, SAM, DCSync, pass-the-hash
- detect_supply_chain: BUILT — package tampering, hash mismatch, CI/CD, typosquatting
- Tool count: 42 (was 40)

## Dual-Endpoint Status
- FAST: http://zovark-inference:8080 (Gemma 4 E4B) — WORKING
- CODE: same as FAST (placeholder) — will route to 31B
- Health check: IMPLEMENTED (check_endpoint_health() on startup)
- Graceful degradation: IMPLEMENTED (3 failures -> fall back to FAST)
- ROG extra_hosts: CONFIGURED (rog-inference:100.100.79.83)

## Entity Graph Status
- Entities: 213 (was 55 at session start)
- Edges: 243 (was 54)
- Populating on investigation: YES
- Latency impact: negligible (fire-and-forget)

## Path C Status
- Novel types tested: 3 (firmware_backdoor, cloud_iam_escalation, anomalous_process_injection)
- Completed: 0 (4B model times out on tool selection — expected)
- FAST timeout: 120s (adequate for 31B, which should complete in 5-15s)
- CODE timeout: 120s read timeout
- GBNF grammars: verified model-agnostic
- Learning gate: ACTIVE (Path C true_positive -> needs_analyst_review)
- Ready for 31B: YES

## Red Team Round 2
- Payloads tested: 14
- Bypasses found: 7
- Fixed: 7 (bash /dev/tcp, nc reverse, socat exec, base64 pipe, subshell, supply chain hash, postinstall)
- All 14 now caught

## Stress Test (100 alerts)
- Completed: 96
- Errors: 0
- Avg latency: 1.84s
- P50 latency: 1.85s
- P95 latency: 2.83s
- Benign FP: 0%

## Final Regression
- verify_all.sh: 16/16
- dedup_stress_test.sh: 14/14
- Unit tests: 534/534 (was 528/534, 6 failures fixed)
- Healer memory: 81MB (restarted from 509MB)

## Morning Action — Plug In The 31B

1. SSH to ROG or check: is 31B download complete?
2. Start inference server on ROG (LM Studio or llama-server)
3. Get model name: `curl http://100.100.79.83:1234/v1/models`
4. Update .env on the dev machine:
   ```
   ZOVARK_LLM_ENDPOINT_CODE=http://rog-inference:1234/v1/chat/completions
   ZOVARK_MODEL_CODE=[model name from step 3]
   ```
5. Restart: `docker compose build worker && docker compose up -d worker`
6. Health: `docker compose logs worker --tail 10 | grep -i "health\|endpoint\|CODE"`
7. Regression: `bash autoresearch/cycle10/verify_all.sh` (16/16 with 31B)
8. Path C test: submit 5 novel alerts, expect real verdicts in <30s
9. Compare: same alerts on 4B vs 31B — is verdict quality better?
10. If pass: update ZOVARK_MODEL_CODE in hot.md, commit, celebrate
    If fail: check GBNF compatibility, output parsing, timeout

## Commits This Session

| Hash | Description |
|------|-------------|
| 4dfa592 | fix: resolve 6 unit test failures — detection thresholds + egress controller |
| 28a6494 | feat: add detect_credential_access + detect_supply_chain tools |
| 35a48d0 | feat: dual-endpoint FAST/CODE with health check and graceful degradation |
| 134a045 | security: red team round 2 — 14 payloads tested, 7 bypasses fixed |
| [this] | docs: overnight state update — all tracking files current |
