# PRD ADDENDUM: Intelligence Layer + Multi-Model Architecture
# Extends: PRD_TEMPLATE_SYNC_ENGINE_v2.md (not yet written)
# Date: 2026-04-05
# Status: PLANNING — base PRD required before execution
# Branch: v3.3-dev

---

> **Note:** This addendum extends Phases 3, 10 and adds Phases 11-15
> of the Template Sync Engine PRD v2. The base PRD (Phases 1-9) has
> not been committed to the repo yet.

---

## STRATEGIC REFRAME

The Template Sync Engine (Phases 1-9) is the delivery mechanism.
It is NOT the product.

The product is:
**Continuous investigation intelligence that tells customers
not just "here are vulnerabilities" but "here's how an attacker
actually wins -- and here's what to fix first."**

This addendum adds:
- Multi-model inference architecture (the brain)
- Attack Path Engine (the crown jewel)
- Contextual Risk Scoring (the prioritizer)
- Closed-Loop Remediation (the feedback system)
- Analyst AI Copilot (the force multiplier)

All of it works offline. All of it is deterministic and auditable.

---

## PHASE 10 (REVISED): MULTI-MODEL INFERENCE ARCHITECTURE

### The Five-Role Model Stack

Replace the "one model for everything" approach with
purpose-built models per reasoning task. The existing
dual-endpoint architecture (FAST/CODE) extends to N roles.

| Role | Model | Where | Purpose |
|------|-------|-------|---------|
| FAST | Mistral 7B Q4 | Local llama-server | Tool selection, param fill (Stage 2) |
| CODE | LLaMA 8B (FT) | Local llama-server | Verdict assessment, summary (Stage 4) |
| REASON | LLaMA 70B | RunPod vLLM | Attack path analysis, complex correlation |
| CODESEC | StarCoder2-7B | Local llama-server | Detection tool code analysis (SAST/DAST) |
| EDGE | Phi-4-mini 3.8B | Edge/constrained | Lightweight agent for minimal hardware |

### Deployment Tier Presets

| Tier | FAST | CODE | REASON | CODESEC | Total Local RAM |
|------|------|------|--------|---------|----------------|
| Edge | Phi-4-mini | Phi-4-mini | OFF | OFF | ~3 GB |
| Dev | Mistral 7B | Mistral 7B | OFF | OFF | ~5 GB |
| Standard | Mistral 7B | LLaMA 8B FT | OFF | StarCoder2 | ~15 GB |
| Professional | Mistral 7B | LLaMA 8B FT | LLaMA 70B (RunPod) | StarCoder2 | ~15 GB local |
| Enterprise | Mistral 7B | LLaMA 70B (RunPod) | LLaMA 70B (RunPod) | StarCoder2 | ~10 GB local |

### Infrastructure: docker-compose.models.yml (new overlay)

Separate inference containers per model. Env vars:
- `ZOVARK_LLM_ENDPOINT_FAST=http://inference-fast:8080/v1/chat/completions`
- `ZOVARK_LLM_ENDPOINT_CODE=http://inference-code:8080/v1/chat/completions`
- `ZOVARK_LLM_ENDPOINT_REASON=https://{runpod}/v1/chat/completions`
- `ZOVARK_LLM_ENDPOINT_CODESEC=http://inference-codesec:8080/v1/chat/completions`

### Semaphore Strategy (per-role)

- FAST: Semaphore(2) -- pipeline-critical, fast
- CODE: Semaphore(2) -- pipeline-critical, slower
- REASON: Semaphore(1) -- background, heavy
- CODESEC: Semaphore(1) -- on-demand, rare

### Fine-Tuning Pipeline for CODE Model

Data sources: 515-alert corpus + AutoResearch alerts + analyst DPO pairs.
Method: LoRA (rank 16, alpha 32) on LLaMA 3.1 8B via Unsloth.
Hardware: Single A100 on RunPod (one-time cost).
Update cadence: Monthly retrain on accumulated feedback.

---

## PHASE 11: ATTACK PATH ENGINE

### Deterministic Correlation (No LLM Required)

Correlates investigations into attack sequences using 5 rule types:
1. Same source IP within 24h window
2. Same target user across alert types (48h)
3. Same host with escalating severity (12h)
4. IOC overlap across investigations (72h)
5. MITRE ATT&CK kill chain phase progression (168h)

### REASON Model Enhancement (Optional)

When Professional/Enterprise tier is available, enriches correlator output
with predictive intelligence: attack objective, containment point,
predicted next technique.

### Database: attack_paths table

Stores: path_id, chain_type, investigation UUIDs, MITRE chain,
composite risk, time span, status, AI enrichment, tenant_id.

---

## PHASE 12: CONTEXTUAL RISK SCORING

### Asset Criticality Model

Database: asset_registry table (identifier, type, criticality 0-100,
exposure, privilege_level, tags, tenant_id).

### Scoring Formula

`contextual_risk = base_risk * criticality_mult * exposure_mult * privilege_mult`

Multipliers:
- Criticality: 0.5x (low) to 2.0x (critical)
- Exposure: 0.7x (isolated) to 1.5x (external)
- Privilege: 1.0x (standard) to 1.8x (system)

Integration: assess.py calls contextual_risk() AFTER base verdict.
Unknown assets get no adjustment.

### Auto-Discovery

Assets appearing in 5+ investigations get suggested for registry.
`zvadmin assets suggest` and `zvadmin assets import <file.csv>`.

---

## PHASE 13: CLOSED-LOOP REMEDIATION TRACKING

### Database: remediation_actions table

Tracks: investigation_id, attack_path_id, action_type, assigned_to,
status (open/in_progress/completed/verified/failed/wont_fix),
verification_method, verification_result.

### Auto-Verification Loop

When remediation marked completed: re-submit synthetic alert of same type.
If new verdict is benign/lower risk -> mark verified.
If still true_positive -> mark failed, reopen.

### External Integration

Push to Jira, ServiceNow, or generic webhook.
Containment playbooks are AST-prefiltered Python scripts.

---

## PHASE 14: AI ANALYST COPILOT

Five capabilities, all local:
1. **Explain** -- why was this flagged?
2. **Suggest** -- what should I do?
3. **Patch** -- generate YARA/Sigma/Snort rules from IOC patterns
4. **Correlate** -- what else is related?
5. **Summarize** -- brief me on last 24 hours

API: POST /api/v1/copilot/{explain,suggest,patch,correlate,brief}

---

## PHASE 15: BUNDLE CONTENT EXPANSION

New bundle content types:
- attack_path_patterns (declarative correlation rules)
- asset_templates (regex-based asset classification)
- remediation_playbooks (AST-prefiltered scripts)
- model_updates (GGUF with SHA-256 + Ed25519 verification)

All new content types go through existing security gates.

---

## REVISED EXECUTION ORDER

| Sprint | Phases | What |
|--------|--------|------|
| A | 1-4 | Foundation: DB schema, bundle system, security gates |
| B | 11-12 | Intelligence: attack paths, contextual risk |
| C | 10 | Multi-model: REASON + CODESEC roles, model swap |
| D | 13-14 | Closed loop: remediation tracking, copilot API |
| E | 7-9, 15 | Delivery: OTA sync, license, expanded bundles |
| F | -- | Fine-tuning: DPO pairs, LoRA training, validation |

---

## SUCCESS CRITERIA

- Attack path correlator finds chains across investigations
- Contextual risk scoring adjusts based on asset criticality
- Remediation tracking creates and verifies fix actions
- Mistral 7B (FAST): 16/16 regression, <5s on GPU
- LLaMA 8B FT (CODE): 16/16 regression, verdict quality >= Gemma baseline
- StarCoder2 (CODESEC): correctly flags malicious tool code
- Model gateway routes correctly per role with fallback chain
