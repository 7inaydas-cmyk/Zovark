# Call Graph: How Code Flows Through Zovark

This document traces exactly which function calls which, for three real investigation scenarios. Think of it like a relay race -- each runner (function) takes the baton and hands it to the next. The indentation shows who is "inside" whom.

---

## Scenario 1: Brute Force Alert (Path A -- Saved Plan, No LLM)

This is the happy path. Zovark already knows how to investigate brute force attacks because there is a pre-built plan sitting in `investigation_plans.json`. No AI needed for tool selection. This path completes in under 2 seconds.

**The relay race:**

```
HTTP POST /api/v1/tasks
```

    **createTaskHandler** (api/task_handlers.go)
    -- Receives the JSON alert from the analyst or SIEM, validates it, extracts tenant_id from JWT.

        **checkPreDedup** (api/alert_dedup.go)
        -- Computes SHA-256 hash of the alert fields and checks Redis. "Have we seen this exact alert recently?" If yes, returns the existing investigation ID and stops here. If no, continues.

        **tryBatchAlert** (api/batch_buffer.go)
        -- Checks if there are other brute force alerts from the same source IP in the last 5 seconds. If yes, absorbs this alert into the batch (one investigation covers them all). If no, continues.

        **checkBackpressure** (api/backpressure.go)
        -- Checks how many workflows are already running. If under 200, green light. If over 1000, returns HTTP 503 "try again later." This is the traffic cop preventing a flood from overwhelming the system.

        INSERT into agent_tasks table (PostgreSQL)
        -- Creates the task record with status "pending."

        **temporalClient.ExecuteWorkflow** (Temporal SDK)
        -- Fires off the investigation as a Temporal workflow. From here, everything is asynchronous.

            **InvestigationWorkflowV2.run** (worker/stages/investigation_workflow.py)
            -- The orchestrator. Calls each pipeline stage as a Temporal "activity" (a fancy word for a function call that Temporal can retry if it fails).

                **fetch_task** (worker/stages/ingest.py)
                -- Loads the full task record from PostgreSQL. The workflow only gets a task ID from Temporal, so it needs to fetch the details.

                **STAGE 1: ingest_alert** (worker/stages/ingest.py)
                -- The front door. Cleans the alert, checks for duplicates, and figures out which skill template to use.

                    **sanitize_siem_event** (worker/stages/input_sanitizer.py)
                    -- Scrubs the alert for injection attacks. Checks 25 patterns (template injection, code injection, SSTI). Normalizes Unicode (strips Cyrillic lookalikes). Truncates fields at 10K characters.

                    **normalize_siem_event** (worker/stages/normalizer.py)
                    -- Maps vendor-specific field names to Zovark standard names. "src_addr" becomes "source_ip," "dst" becomes "destination_ip." Handles 70+ field mappings across Splunk, Elastic, and firewall formats.

                    **_check_exact_dedup** (worker/stages/ingest.py)
                    -- Redis dedup check at the worker level (complements the Go API dedup). Computes SHA-256 of canonical fields with timestamps stripped out.

                    **_register_dedup** (worker/stages/ingest.py)
                    -- If not a duplicate, registers this alert in Redis so future copies are caught. TTL varies by severity (critical=60s, low=3600s).

                    **_mask_pii** (worker/stages/ingest.py)
                    -- Scans for AWS keys, SSNs, API tokens. Replaces them with placeholders like [AWS_KEY_0]. Prevents secrets from reaching the LLM.

                    **_retrieve_skill** (worker/stages/ingest.py)
                    -- Queries the agent_skills table: "Do we have a template for brute_force?" Yes -- returns the brute-force-investigation skill with its investigation plan pointer. This is what makes Path A possible.

                    **_has_raw_log_attack_content** (worker/stages/ingest.py)
                    -- Even though brute force is not benign, this function is ready. If the skill had matched "benign-system-event," this function would scan the raw log against 70 attack patterns. If it found attack commands hiding behind benign metadata, it would override the benign routing and force a full investigation. This is the red-team-proof safety net.

                **STAGE 2: analyze_alert** (worker/stages/analyze.py)
                -- Decides HOW to investigate. For brute force, the answer is simple: use the saved plan.

                    **_analyze_v3_tools** (worker/stages/analyze.py)
                    -- The V3 routing function. First checks: "Does the skill from ingest have an investigation_plan?" For brute_force, yes.

                        Queries agent_skills table for investigation_plan column.
                        -- Finds the brute_force plan: 7 tools in sequence.

                        Returns AnalyzeOutput with path_taken="A", source="saved_plan"
                        -- No LLM called. No tokens burned. This took about 5 milliseconds.

                **STAGE 3: execute_investigation** (worker/stages/execute.py)
                -- Dispatches to the tool runner.

                    **execute_plan** (worker/tools/runner.py)
                    -- The engine room. Takes the 7-step plan and runs each tool in sequence, piping outputs forward.

                        **Step 1: _run_single_step** calls **parse_auth_log** (worker/tools/parsing.py)
                        -- Parses the raw log into structured fields: action=failed, username=root, source_ip=185.220.101.45, method=password.

                        **Step 2: _run_single_step** calls **extract_ipv4** (worker/tools/extraction.py)
                        -- Pulls all IPv4 addresses from the raw log with evidence_refs (snippets showing where each IP was found).

                        **Step 3: _run_single_step** calls **extract_usernames** (worker/tools/extraction.py)
                        -- Extracts usernames like "root" from patterns like "Failed password for root."

                        **Step 4: _run_single_step** calls **count_pattern** (worker/tools/analysis.py)
                        -- Counts how many "Failed password" lines appear. If it finds 500, that is strong evidence of brute force.

                            **_resolve_args** (worker/tools/runner.py)
                            -- Resolves variable references. The plan says "text: $raw_log" -- this function swaps $raw_log with the actual log text. It also resolves $step2.count to get the IP count from step 2.

                        **Step 5: _run_single_step** calls **score_brute_force** (worker/tools/scoring.py)
                        -- Takes failed_count, unique_sources, and timespan. With 500 failures from 1 IP in 5 minutes, this returns risk_score=95.

                        **Step 6: _run_single_step** calls **correlate_with_history** (worker/tools/enrichment.py)
                        -- Checks if 185.220.101.45 has appeared in previous investigations. If yes, returns prior verdicts and risk scores. This is where the entity graph pays off.

                        **Step 7: _run_single_step** calls **map_mitre** (worker/tools/enrichment.py)
                        -- Maps the attack to MITRE ATT&CK technique T1110 (Brute Force). Returns the technique name and tactic.

                        **_derive_verdict** (worker/tools/runner.py)
                        -- With risk_score=95 and 3+ IOCs, returns verdict="true_positive."

                **STAGE 4: assess_results** (worker/stages/assess.py)
                -- The quality control layer. Validates everything the tools produced.

                    **validate_investigation_output** (worker/stages/output_validator.py)
                    -- Schema check: are findings a list? Is risk_score 0-100? Are IOC types valid? If validation fails, uses safe_default_output instead of crashing.

                    **_extract_iocs_from_signals** (worker/stages/assess.py)
                    -- Comprehensive IOC extraction from SIEM data. Pulls IPs, URLs, emails, hashes, domains, CVEs. Attaches evidence_refs (log snippets proving the IOC exists in the data).

                    **Signal boost check** (worker/stages/assess.py)
                    -- Scans raw_log against 11 attack patterns (SQLi, XSS, C2 beaconing). For brute force, no boost needed -- the scoring tool already gave risk=95.

                    **Suppression detection** (worker/stages/assess.py)
                    -- Checks for adversarial phrases like "scheduled test" or "do not escalate" in the alert. If found alongside attack indicators, BOOSTS risk to 75+ instead of lowering it. This catches attackers who try to trick the system.

                    **IOC provenance validation** (worker/stages/assess.py)
                    -- For each IOC, checks: "Does this value actually appear in the raw log?" If an IP only appears in a structured field but not in the log text, it gets downgraded to confidence=low. This prevents hallucinated IOCs.

                    **_derive_verdict** (worker/stages/assess.py)
                    -- Final verdict with risk=95, 3+ confirmed IOCs: true_positive.

                    **get_mitre_techniques** (worker/stages/mitre_mapping.py)
                    -- Maps the task_type to MITRE ATT&CK techniques. Brute force maps to T1110.

                    **_generate_plain_english** (worker/stages/assess.py)
                    -- Writes a bullet-point summary for L1 analysts: "CONFIRMED ATTACK from 185.220.101.45, 500 failed logins for root, HIGH RISK (95/100), MITRE T1110."

                **STAGE 4.5: apply_governance** (worker/stages/govern.py)
                -- The human oversight checkpoint.

                    **_get_governance_config** (worker/stages/govern.py)
                    -- Queries the governance_config table for this tenant. Default is "observe" mode.

                    In observe mode: sets needs_human_review=true, review_reason="Observe mode: all investigations require analyst review."
                    -- Even though the system is confident this is a real attack, an analyst must confirm it before automated remediation can kick in. This is by design for regulated environments.

                **STAGE 5: store_investigation** (worker/stages/store.py)
                -- Writes everything to the database. This is the "permanent record."

                    SET LOCAL app.current_tenant (PostgreSQL RLS)
                    -- Sets the Row Level Security context so this tenant can only see their own data.

                    **_insert_audit_event** (worker/stages/store.py)
                    -- Writes "investigation_started" to the audit trail. Required for compliance (CMMC, HIPAA).

                    **_update_task_status** (worker/stages/store.py)
                    -- Updates agent_tasks with verdict, risk_score, all IOCs, findings, MITRE techniques, plain-English summary, path_taken="A", execution_mode="tools." Uses synchronous_commit for durability (the database confirms it wrote to disk, not just to memory).

                    **_save_pattern** (worker/stages/store.py)
                    -- Saves to investigation_memory table. "Here is what we found when we investigated brute_force with this rule_name." Future investigations can reference this.

                    **_create_investigation** (worker/stages/store.py)
                    -- Inserts into the investigations table with verdict, risk_score, confidence, and the summary.

                    **_insert_audit_event** (worker/stages/store.py)
                    -- Writes "investigation_completed" with full metadata (verdict, risk, IOC count, execution time).

                    **persist_entities** (worker/intelligence/entity_graph.py)
                    -- UPSERTs each IOC as an entity node. If 185.220.101.45 already exists from a prior investigation, increments observation_count and updates last_seen. If new, creates the node with threat_score=95.

                    **infer_relationships** (worker/intelligence/entity_graph.py)
                    -- Deterministically creates edges: source_ip communicates_with dest_ip, source_ip logged_into username.

                    **persist_edges** (worker/intelligence/entity_graph.py)
                    -- Writes the relationship edges to entity_edges table.

                    **persist_cross_tenant** (worker/intelligence/entity_graph.py)
                    -- Updates the privacy-preserving cross-tenant table. Other tenants can see "this IP hash has been seen as malicious 5 times" without seeing the actual IP or which tenant reported it.

                    NOTIFY task_completed (PostgreSQL)
                    -- Fires a PostgreSQL notification that the SSE endpoint picks up. The React dashboard gets a real-time event: "Investigation complete, true_positive, risk 95."

                    **_update_dedup_entry** (worker/stages/store.py)
                    -- Updates the Redis dedup entry with the final verdict and risk_score, so if the same alert arrives again, the dedup layer knows the prior investigation succeeded.

---

## Scenario 2: Novel Attack "firmware_backdoor" (Path C -- LLM Selects Tools)

This is the hard path. Zovark has never seen "firmware_backdoor" before. There is no saved plan, no template, no alias. The system must ask the AI to figure out which tools to run. This path takes 5-30 seconds depending on the LLM.

**The first three layers are identical to Scenario 1** (createTaskHandler, dedup, batch, backpressure, Temporal). We pick up at the pipeline stages:

                **STAGE 1: ingest_alert** -- Same as Scenario 1.
                -- sanitize, normalize, dedup, PII mask. But _retrieve_skill finds no matching skill for "firmware_backdoor," so skill_id is empty.

                **STAGE 2: analyze_alert** (worker/stages/analyze.py)

                    **_analyze_v3_tools** (worker/stages/analyze.py)
                    -- The routing function tries four lookups, all fail:

                        **Lookup 1 -- Saved skill plan:** No skill_id from ingest. Skip.

                        **Lookup 2 -- Exact match in investigation_plans.json:** No "firmware_backdoor" key. Skip.

                        **Lookup 3 -- Alias match via _PLAN_ALIASES:** No alias for "firmware_backdoor." Skip.

                        **Lookup 4 -- Substring match:** No plan key starts with "firmware" or contains "firmware_backdoor." Skip.

                        **Lookup 5 -- Benign check:** "firmware_backdoor" is not in the benign list and does not match benign patterns. Skip.

                    All plan lookups exhausted. Falls through to LLM Path C.

                    **get_catalog_text** (worker/tools/catalog.py)
                    -- Formats all 40 tools into a text catalog: name, arguments, description. This becomes part of the LLM prompt so the AI knows what tools are available.

                    **_load_institutional_knowledge** (worker/stages/analyze.py)
                    -- Queries the institutional_knowledge table: "Do we know anything about the entities in this alert?" If the source IP is a known developer workstation, the AI gets that context.

                    Builds system prompt with _TOOL_CALLING_SYSTEM_PREFIX
                    -- Static prompt (cached by llama-server's prefix cache): "Select 3-8 tools. Start with extraction/parsing. End with correlate and map_mitre."

                    **llm_call** (worker/stages/llm_gateway.py)
                    -- Routes to the FAST model (Gemma 4 E4B). Uses GBNF grammar to constrain the output to valid JSON. The grammar literally makes it impossible for the model to output anything except a JSON object with a "steps" array containing tool names from the catalog.

                    **_parse_tool_plan** (worker/stages/analyze.py)
                    -- Validates the LLM response. Checks every tool name against TOOL_CATALOG (rejects hallucinated tools). Removes duplicates. Caps at 10 tools. For firmware_backdoor, the LLM might select: extract_hashes, extract_ipv4, parse_windows_event, detect_lolbin_abuse, score_generic, correlate_with_history, map_mitre.

                    Returns AnalyzeOutput with path_taken="C", source="llm_tool_call"

                **STAGE 3: execute_investigation** -- Same runner as Scenario 1.
                -- Runs the LLM-selected tools. Variable resolution, per-tool timeouts, error isolation all work the same way.

                **STAGE 4: assess_results** -- Same validation, IOC extraction, signal boost.
                -- But with one critical addition:

                    **Learning gate check** (worker/stages/assess.py)
                    -- Because path_taken="C" (LLM-selected tools, not a pre-validated plan), the verdict is downgraded to needs_analyst_review. This is the template promotion flywheel: an analyst must confirm the verdict. If the analyst confirms, this plan can be saved as a template for future firmware_backdoor alerts, converting them from slow Path C to fast Path A.

                **STAGE 4.5: apply_governance** -- Same as Scenario 1.
                -- In observe mode, needs_human_review is already true.

                **STAGE 5: store_investigation** -- Same as Scenario 1.
                -- Entity graph, audit events, NOTIFY. The key difference: path_taken="C" is stored, so the template promotion system knows this investigation is a candidate for promotion.

---

## Scenario 3: Repeat Offender IP (Entity Graph Enrichment)

This scenario is identical to Scenario 1 (brute force, Path A), except the attacker IP 185.220.101.45 has appeared in TWO previous investigations. This is where the entity graph changes the outcome.

**Stages 1-2: identical to Scenario 1.**

**Stage 3 -- Execute, with enrichment:**

                        **Step 6: correlate_with_history** (worker/tools/enrichment.py)
                        -- This is where the magic happens. The tool queries the entity graph:

                            Checks history_context (pre-loaded by _load_correlation_context in analyze.py)
                            -- Finds two prior investigations involving 185.220.101.45:
                               - 3 days ago: brute_force, verdict=true_positive, risk=88
                               - 1 day ago: lateral_movement, verdict=true_positive, risk=92

                            Returns: risk_modifier="increase", reason="IP seen in 2 prior attacks (brute_force, lateral_movement) in last 7 days", prior_max_risk=92, observation_count=3.

                        The tool runner sees the risk_modifier and adjusts the aggregated risk score upward. Instead of "just" 95 from score_brute_force, the combined evidence is even stronger.

**Stage 4 -- Assess:**
-- IOC provenance validation sees that 185.220.101.45 is confirmed in raw_log (confidence=high). The prior investigation history increases the overall confidence. The plain-English summary now includes: "This IP has been involved in 2 prior attacks including lateral movement."

**Stage 5 -- Store:**

                    **persist_entities** (worker/intelligence/entity_graph.py)
                    -- The UPSERT for 185.220.101.45 hits the ON CONFLICT clause. Instead of creating a new entity, it:
                       - Increments observation_count from 2 to 3
                       - Updates last_seen to now
                       - Takes the GREATEST of the old threat_score and the new one
                       - Updates confidence to the higher of the two values

                    **persist_cross_tenant** (worker/intelligence/entity_graph.py)
                    -- The cross-tenant record also gets updated: sighting_count goes up, avg_risk_score is recalculated as a running average, malicious_count increments by 1.

This is the flywheel effect: every investigation makes the next one better. The entity graph accumulates institutional memory that no individual investigation could have.
