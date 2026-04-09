"""
ZOVARK Investigation Pipeline — 5-Stage Architecture

Stage 1: INGEST  — dedup, PII mask, validate (no LLM)
Stage 2: ANALYZE — template/LLM/stub code generation (LLM contained here)
Stage 3: EXECUTE — sandbox, AST check (no LLM)
Stage 4: ASSESS  — verdict, memory, FP analysis (LLM for entity extraction + FP)
Stage 5: STORE   — DB writes, entity graph, reports (no LLM)

Each stage has typed input/output contracts via dataclasses.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Literal


@dataclass
class IngestOutput:
    """Stage 1 output — validated, deduplicated, PII-masked alert."""
    task_id: str
    tenant_id: str
    task_type: str
    siem_event: Dict = field(default_factory=dict)
    prompt: str = ""
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    dedup_reason: Optional[str] = None
    pii_masked: bool = False
    pii_entity_map_key: Optional[str] = None
    skill_id: Optional[str] = None
    skill_template: Optional[str] = None
    skill_params: List[Dict] = field(default_factory=list)
    skill_methodology: str = ""


@dataclass
class AnalyzeOutput:
    """Stage 2 output — generated investigation code (v2) or tool plan (v3)."""
    code: str = ""
    source: Literal["template", "llm", "stub", "fast_fill", "saved_plan", "llm_tool_call", "none", "error"] = "llm"
    path_taken: Literal["A", "B", "C", "benign", "unknown", "error_llm_down", "error_no_plan"] = "unknown"
    skill_id: Optional[str] = None
    preflight_passed: bool = True
    preflight_fixes: List[str] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    generation_ms: int = 0
    # v3 tool-calling fields
    plan: List[Dict] = field(default_factory=list)
    execution_mode: str = "sandbox"  # "sandbox" (v2) or "tools" (v3)


@dataclass
class ExecuteOutput:
    """Stage 3 output — sandbox execution results."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    status: Literal["completed", "failed", "timeout"] = "failed"
    iocs: List[Dict] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    risk_score: int = 0
    recommendations: List[str] = field(default_factory=list)
    execution_ms: int = 0
    retries_used: int = 0
    # v3 fields
    execution_mode: str = "sandbox"  # "sandbox", "tools", "sandbox_fallback", "failed"
    path_d_fallback: bool = False
    path_d_reason: str = ""
    tools_executed: int = 0  # v3: number of tools that ran (for validator context)


@dataclass
class AssessOutput:
    """Stage 4 output — verdict and enrichment."""
    verdict: Literal["true_positive", "suspicious", "benign", "inconclusive", "needs_manual_review", "needs_analyst_review"] = "inconclusive"
    risk_score: int = 0
    severity: Literal["critical", "high", "medium", "low", "informational"] = "medium"
    confidence: float = 0.5
    false_positive_confidence: float = 0.0
    entities: List[Dict] = field(default_factory=list)
    edges: List[Dict] = field(default_factory=list)
    blast_radius: Dict = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    memory_summary: str = ""


@dataclass
class StoreOutput:
    """Stage 5 output — persistence confirmation."""
    task_id: str = ""
    status: Literal["completed", "failed"] = "completed"
    investigation_id: Optional[str] = None
    entities_stored: int = 0
    edges_stored: int = 0
    memory_saved: bool = False
    pattern_saved: bool = False
    playbooks_triggered: List[str] = field(default_factory=list)
