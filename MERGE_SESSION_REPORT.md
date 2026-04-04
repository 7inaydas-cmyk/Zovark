# Merge Session Report — v3.2.1
Date: 2026-04-04
Branch: master (tagged v3.2.1), dev continues on v3.3-dev

## Feature A: MITRE Propagation Fix

```
FEATURE A RESULTS: MITRE PROPAGATION FIX
=========================================
Bug pattern found:         Pattern 2 (static map missing entries)
Root cause:                mitre_mapping.py MITRE_MAP missing 12 task_type keys
                           (kerberoasting, golden_ticket, dns_exfiltration, lolbin_abuse,
                            dcsync, dll_sideloading, process_injection, wmi_lateral,
                            rdp_tunneling, powershell_obfuscation, credential_access, api_key_abuse)
Fix applied in:            worker/stages/mitre_mapping.py (added 12 entries to MITRE_MAP)
MITRE coverage before:     6/10 attack types (60%)
MITRE coverage after:      10/10 attack types (100%)
Plans with map_mitre:      23/24 (all except benign)
Regression:                15/15
DECISION:                  KEEP
```

## Feature B: Plan Parallelism

```
FEATURE B RESULTS: PLAN PARALLELISM
=====================================
Plans restructured:        0/24 (not needed — already parallel-ready)
Root cause found:          has_conditionals guard in runner.py disabled parallel for
                           ALL plans if ANY step had a condition. Only 3/24 plans have
                           conditionals, but they were blocking all 24.
Fix applied:               Removed has_conditionals guard (conditions handled correctly
                           by dependency graph — they have $stepN refs that create proper deps)
Batch improvement (all 24 plans):
  brute_force:       [1,1,1,1,1,1,1] → [5,2]
  phishing:          [1,1,1,1,1,1,1,1,1,1] → [8,2]
  ransomware:        [1,1,1,1,1,1,1,1] → [7,1]
  lateral_movement:  [1,1,1,1,1,1,1,1] → [6,2]
  priv_esc:          [1,1,1,1,1,1,1,1,1,1] → [8,2]
  (all others show similar improvement)
Regression (parallel ON):  15/15
Regression (parallel OFF): 15/15
Verdict drift:             NONE
DECISION:                  KEEP
```

## Feature C: Merge to Master

```
FEATURE C RESULTS: MERGE TO MASTER
====================================
Merge conflicts:        0
Files changed:          200+
Regression on master:   15/15
Tag created:            v3.2.1
Dev branch created:     v3.3-dev
DECISION:               COMPLETE
```

## Updated Project State
- Version: v3.2.1 on master (tagged), dev on v3.3-dev
- Model: Gemma 4 E4B Q4_K_M (5.0GB, --ctx-size 4096)
- Regression: 15/15
- MITRE coverage: 100% (10/10 attack types)
- Parallel plans: 24/24 eligible (3 with conditionals now included)
- Branch: v3.3-dev (development continues here)

## v3.3 Roadmap
1. Healthcare template pack (30 templates)
2. Build web-admin frontend
3. A100 benchmark with parallel workers
4. Switch to zovark_app DB user (RLS enforcement)
5. Customer tier dual-inference test
6. Blue/green deployment
