# Zovark v3.3 — Gemma 4 26B-A4B Benchmark

Generated: 2026-04-09

## Model Configuration

| Role | Model | Endpoint | Engine | Speed |
|------|-------|----------|--------|-------|
| FAST (tool selection, param fill) | Gemma 4 E4B Q4_K_M | Local (zovark-inference:8080) | llama-server | ~30 tok/s |
| CODE (verdict, summary, Path C) | Gemma 4 26B-A4B | ROG (100.100.79.83:8080) | llama-server | 77 tok/s gen, 244 tok/s prompt |

### Why 26B-A4B over 31B Dense
- **Architecture:** 26B-A4B is Mixture of Experts (MoE) — activates 4B parameters per token from a 26B total
- **Speed:** 77 tok/s vs ~15 tok/s for 31B dense on the same 4090
- **Quality:** Comparable reasoning quality to 31B dense due to expert routing
- **VRAM:** Fits in 24GB (4090) with room for KV cache
- **Latency:** Path C tool selection: ~7s (vs timeout on 31B dense)

### Why Ollama was Rejected
- Supply chain risk: PyPI-adjacent dependency chain
- Incompatible with GBNF grammar (llama-server native feature)
- `reasoning_content` field not handled by OpenAI-compat API
- llama-server is already deployed and proven in production

## Regression Results

| Test | Result | Notes |
|------|--------|-------|
| verify_all.sh | 16/16 | All attacks detected, all benign correct |
| Unit tests | 534/534 | Zero failures |
| Dedup stress | 14/14 | All dedup scenarios pass |

## Path C Results (Novel Attack Types)

| Alert Type | Path | Verdict | Risk | Seconds | Notes |
|-----------|------|---------|------|---------|-------|
| unusual_network_traffic | C | benign | 0 | 7 | Generic payload — correct classification |

Path C tool selection: 26B selects tools from 42-tool catalog via GBNF grammar in ~5s.
Total Path C latency: ~7s (tool selection + execution + assess).

**Before 26B:** Path C always timed out (120s) on the local 4B — fail-closed to needs_manual_review.
**After 26B:** Path C completes in 7s with real verdicts.

## Path A Results (Saved Plans + 26B Assess)

All Path A attacks use local 4B for tool execution (deterministic, ~1s).
26B generates summaries in assess stage (~15s per alert).

| Type | Risk | Verdict | Latency |
|------|------|---------|---------|
| brute_force | 95 | true_positive | ~15s |
| phishing | 85 | true_positive | ~27s* |
| ransomware | 100 | true_positive | ~38s* |
| kerberoasting | 80 | true_positive | ~52s* |

*Latency includes semaphore queue wait (CODE semaphore=1, serialized)

## Benign Results

All benign alerts skip 26B (template summary, no LLM needed).
Latency: 0-2s. Risk: 0. Verdict: benign. 0% false positive rate.

## Known Limitations

1. **GBNF + thinking tokens:** Some alerts produce JSON with control characters from Gemma 4's thinking mode. GBNF grammar constrains output structure but thinking tokens can leak. Edge case — most alerts parse correctly.

2. **Semaphore serialization:** CODE semaphore(1) means 26B requests serialize. With 10 concurrent attacks, the last alert waits ~150s. Increasing to semaphore(2) would help but risks GPU contention.

3. **Summary generation:** 26B summaries require `reasoning_effort: "none"` for prose output. With grammar, thinking is needed for quality tool selection.

## Architecture

```
SIEM Alert → Go API → Temporal → Worker

Path A (saved plan):
  FAST (4B local) → tool execution → 26B (ROG) assess summary → verdict

Path C (novel type):
  26B (ROG) tool selection via GBNF → tool execution → 26B (ROG) assess summary → verdict

Benign:
  Template (no LLM) → verdict
```

## Infrastructure

- ROG: ASUS ROG, RTX 4090 24GB, Tailscale IP 100.100.79.83
- Local: Dev machine, Gemma 4 E4B on local GPU
- Network: Tailscale mesh (100.100.x.x), extra_hosts in docker-compose.yml
- Failover: If CODE endpoint unreachable (3 failures), degrades to FAST
