# HOT CACHE
# Updated: 2026-04-09 (26B connected)
# Read this FIRST. Skip CLAUDE.md unless you need deep detail.

## Current State
- Branch: v3.3-dev
- Regression: 16/16 (with 26B connected)
- Unit tests: 534/534
- Tools: 42 (detect_credential_access + detect_supply_chain)
- Content scanner: 87 patterns, signal boost: 11
- FAST: Gemma 4 E4B (local, llama-server, ~30 tok/s)
- CODE: Gemma 4 26B-A4B (ROG 100.100.79.83, llama-server, 77 tok/s)
- Path C: WORKING — 7s for novel types (was: timeout on 4B)
- Benign: 0-2s, 0% FP (skips LLM entirely)
- Entity graph: 213 entities, 243 edges

## Dual-Endpoint (LIVE)
- FAST: http://zovark-inference:8080 (Gemma 4 E4B, local)
- CODE: http://100.100.79.83:8080 (Gemma 4 26B-A4B, ROG via Tailscale)
- Health check: check_endpoint_health() on startup
- Degradation: 3 CODE failures → fall back to FAST
- Ollama: BANNED (supply chain risk, GBNF incompatible)
- Gemma 4 thinking: reasoning_effort=none for prose, thinking enabled for GBNF grammar

## Known Issues
- GBNF + thinking tokens: some Path C alerts produce control characters in JSON (edge case)
- CODE semaphore(1): serializes 26B requests — last alert in burst waits ~150s
- assess summary timeout raised to 90s (was 45s)

## Sprint C — COMPLETE
- C1: Remediation engine — DONE
- C2: Copilot API — DONE
- C3: License enforcement — DONE

## Next Sprint: D — Bundle Distribution
- D1: zvadmin bundle CLI
- D2: OTA sync service

## Anti-Patterns
- Don't use .* in regex (ReDoS) — split into independent re.search() calls
- Don't use fmt.Sprintf for JSON — use json.Marshal
- Don't use Ollama — llama-server only
- reasoning_effort=none for prose, thinking enabled for GBNF grammar
- License check errors → DENY (fail-closed, Invariant #6)
