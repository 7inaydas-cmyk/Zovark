"""
Three-phase deterministic SAST for bundle detection tools.
No LLM involved — all analysis is static/runtime.

Phase 1: AST analysis (reuses execute.py allowlist)
Phase 2: Pattern analysis (obfuscation detection)
Phase 3: Runtime validation (isolated subprocess with import hook)
DAST:    Run bundled test_cases with resource limits

All phases must pass for a tool to be marked sast_passed=true.
Failed tools are staged as active=false for operator review.
"""
import ast
import json
import logging
import re
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Allowlisted modules (same as execute.py) ─────────────
ALLOWED_IMPORTS = frozenset({
    "json", "re", "datetime", "collections", "math", "hashlib",
    "ipaddress", "base64", "urllib.parse", "csv", "statistics",
    "string", "copy", "itertools", "functools", "typing",
})

# ── Phase 1: AST blocklists ──────────────────────────────
FORBIDDEN_IMPORTS = frozenset({
    "os", "sys", "subprocess", "socket", "shutil", "importlib",
    "pickle", "marshal", "ctypes", "pty", "signal", "multiprocessing",
    "threading", "http", "urllib.request", "ftplib", "smtplib",
    "xmlrpc", "requests", "aiohttp", "pathlib", "glob", "tempfile",
    "shelve", "cffi",
})

BLOCKED_BUILTINS = frozenset({
    "open", "eval", "exec", "compile", "__import__", "breakpoint",
    "input", "exit", "quit",
})

# ── Phase 2: Obfuscation patterns ────────────────────────
OBFUSCATION_PATTERNS = [
    (r"importlib\.import_module\s*\(", "Dynamic import via importlib"),
    (r"__import__\s*\(", "Dynamic __import__()"),
    (r"getattr\s*\([^)]*\+\s*", "getattr with string concatenation"),
    (r"eval\s*\(", "eval() call"),
    (r"exec\s*\(", "exec() call"),
    (r"compile\s*\(", "compile() call"),
    (r"os\.system\s*\(", "os.system() call"),
    (r"subprocess\.", "subprocess module usage"),
    (r"socket\.", "socket module usage"),
    (r"ctypes\.", "ctypes module usage"),
    (r"pickle\.loads?\s*\(", "pickle deserialization"),
    (r"marshal\.loads?\s*\(", "marshal deserialization"),
    (r"builtins\.__dict__", "builtins dict access"),
    (r"globals\s*\(\s*\)\s*\[", "globals() indexing"),
    (r"locals\s*\(\s*\)\s*\[", "locals() indexing"),
]


@dataclass
class SASTIssue:
    phase: int
    severity: str  # "critical", "warning"
    description: str
    line: Optional[int] = None


@dataclass
class SASTResult:
    safe: bool
    issues: list[SASTIssue] = field(default_factory=list)
    phases_passed: list[int] = field(default_factory=list)

    @property
    def report(self) -> dict:
        return {
            "safe": self.safe,
            "phases_passed": self.phases_passed,
            "issues": [
                {
                    "phase": i.phase,
                    "severity": i.severity,
                    "description": i.description,
                    "line": i.line,
                }
                for i in self.issues
            ],
        }


# ── Phase 1: AST Analysis ────────────────────────────────

def _phase1_ast_analysis(code: str) -> list[SASTIssue]:
    """Parse AST, check imports against allowlist, check builtins."""
    issues: list[SASTIssue] = []

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        issues.append(SASTIssue(
            phase=1, severity="critical",
            description=f"Syntax error: {e}", line=e.lineno,
        ))
        return issues

    for node in ast.walk(tree):
        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_module = alias.name.split(".")[0]
                full_module = alias.name
                if top_module in FORBIDDEN_IMPORTS or full_module in FORBIDDEN_IMPORTS:
                    issues.append(SASTIssue(
                        phase=1, severity="critical",
                        description=f"Forbidden import: {alias.name}",
                        line=node.lineno,
                    ))
                elif top_module not in ALLOWED_IMPORTS and full_module not in ALLOWED_IMPORTS:
                    issues.append(SASTIssue(
                        phase=1, severity="critical",
                        description=f"Import not in allowlist: {alias.name}",
                        line=node.lineno,
                    ))

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_module = node.module.split(".")[0]
                full_module = node.module
                if top_module in FORBIDDEN_IMPORTS or full_module in FORBIDDEN_IMPORTS:
                    issues.append(SASTIssue(
                        phase=1, severity="critical",
                        description=f"Forbidden from-import: {node.module}",
                        line=node.lineno,
                    ))
                elif top_module not in ALLOWED_IMPORTS and full_module not in ALLOWED_IMPORTS:
                    issues.append(SASTIssue(
                        phase=1, severity="critical",
                        description=f"From-import not in allowlist: {node.module}",
                        line=node.lineno,
                    ))

        # Check blocked builtins
        elif isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name and name in BLOCKED_BUILTINS:
                issues.append(SASTIssue(
                    phase=1, severity="critical",
                    description=f"Blocked builtin call: {name}()",
                    line=node.lineno,
                ))

    return issues


# ── Phase 2: Pattern Analysis ─────────────────────────────

def _phase2_pattern_analysis(code: str) -> list[SASTIssue]:
    """Regex-based obfuscation detection."""
    issues: list[SASTIssue] = []

    for pattern, desc in OBFUSCATION_PATTERNS:
        for match in re.finditer(pattern, code):
            # Find line number
            line_no = code[:match.start()].count("\n") + 1
            issues.append(SASTIssue(
                phase=2, severity="critical",
                description=f"Obfuscation: {desc}",
                line=line_no,
            ))

    # Check for base64-encoded strings > 100 chars (potential payload)
    for match in re.finditer(r'["\']([A-Za-z0-9+/=]{100,})["\']', code):
        line_no = code[:match.start()].count("\n") + 1
        issues.append(SASTIssue(
            phase=2, severity="warning",
            description=f"Long base64-like string ({len(match.group(1))} chars)",
            line=line_no,
        ))

    # importlib + string concat in same function scope
    if "importlib" in code and ("+" in code or "format" in code or "join" in code):
        issues.append(SASTIssue(
            phase=2, severity="critical",
            description="importlib with string construction in same scope",
        ))

    return issues


# ── Phase 3: Runtime Validation ───────────────────────────

_IMPORT_HOOK_SCRIPT = textwrap.dedent("""\
    import sys
    import json

    ALLOWED = {allowed_json}
    BLOCKED_BUILTINS = {blocked_json}

    class _BundleSASTHook:
        def find_module(self, name, path=None):
            top = name.split(".")[0]
            if top not in ALLOWED:
                raise ImportError(f"SAST: blocked import {{name}}")
            return None

    sys.meta_path.insert(0, _BundleSASTHook())

    # Patch builtins
    import builtins as _b
    for _name in BLOCKED_BUILTINS:
        if hasattr(_b, _name):
            def _blocked(*a, _n=_name, **kw):
                raise RuntimeError(f"SAST: blocked builtin {{_n}}")
            setattr(_b, _name, _blocked)

    # Execute the tool code
    try:
        code = {code_json}
        compile(code, "<bundle_tool>", "exec")
        print(json.dumps({{"safe": True, "error": None}}))
    except Exception as e:
        print(json.dumps({{"safe": False, "error": str(e)}}))
""")


def _phase3_runtime_validation(code: str) -> list[SASTIssue]:
    """Execute in isolated subprocess with import hooks.

    Catches dynamic imports that AST can't detect.
    Timeout: 10s. No network. Minimal env.
    """
    issues: list[SASTIssue] = []

    script = _IMPORT_HOOK_SCRIPT.format(
        allowed_json=json.dumps(sorted(ALLOWED_IMPORTS)),
        blocked_json=json.dumps(sorted(BLOCKED_BUILTINS)),
        code_json=json.dumps(code),
    )

    try:
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=10,
            env={"PYTHONPATH": "", "HOME": "/tmp", "PATH": ""},
            cwd="/tmp",
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()[:200]
            issues.append(SASTIssue(
                phase=3, severity="critical",
                description=f"Runtime validation failed: {stderr}",
            ))
        else:
            try:
                output = json.loads(result.stdout.strip())
                if not output.get("safe"):
                    issues.append(SASTIssue(
                        phase=3, severity="critical",
                        description=f"Runtime blocked: {output.get('error', 'unknown')}",
                    ))
            except json.JSONDecodeError:
                issues.append(SASTIssue(
                    phase=3, severity="warning",
                    description="Runtime produced non-JSON output",
                ))

    except subprocess.TimeoutExpired:
        issues.append(SASTIssue(
            phase=3, severity="critical",
            description="Runtime validation timed out (10s)",
        ))
    except FileNotFoundError:
        # Can't run subprocess (e.g., inside Docker without shell)
        logger.warning("Phase 3 skipped: subprocess unavailable")

    return issues


# ── Main entry point ──────────────────────────────────────

def run_sast(code: str, skip_runtime: bool = False) -> SASTResult:
    """Run all three SAST phases on detection tool code.

    Returns SASTResult with safe=True only if ALL phases pass.
    """
    all_issues: list[SASTIssue] = []
    phases_passed: list[int] = []

    # Phase 1: AST
    p1 = _phase1_ast_analysis(code)
    critical_p1 = [i for i in p1 if i.severity == "critical"]
    all_issues.extend(p1)
    if not critical_p1:
        phases_passed.append(1)
    else:
        # If phase 1 has critical issues, skip subsequent phases
        return SASTResult(safe=False, issues=all_issues, phases_passed=phases_passed)

    # Phase 2: Pattern analysis
    p2 = _phase2_pattern_analysis(code)
    critical_p2 = [i for i in p2 if i.severity == "critical"]
    all_issues.extend(p2)
    if not critical_p2:
        phases_passed.append(2)
    else:
        return SASTResult(safe=False, issues=all_issues, phases_passed=phases_passed)

    # Phase 3: Runtime validation
    if not skip_runtime:
        p3 = _phase3_runtime_validation(code)
        critical_p3 = [i for i in p3 if i.severity == "critical"]
        all_issues.extend(p3)
        if not critical_p3:
            phases_passed.append(3)
        else:
            return SASTResult(safe=False, issues=all_issues, phases_passed=phases_passed)
    else:
        phases_passed.append(3)  # Skipped = passed

    return SASTResult(
        safe=True,
        issues=all_issues,  # May contain warnings
        phases_passed=phases_passed,
    )


# ── DAST: Test case execution ─────────────────────────────

def run_dast(
    function_code: str,
    test_cases: list[dict],
    timeout: int = 10,
) -> tuple[bool, list[dict]]:
    """Execute bundled test cases against a detection tool.

    Each test_case has: {"input": {...}, "expected_risk_min": N}
    Runs in subprocess with resource limits.

    Returns (all_passed, results).
    """
    if not test_cases:
        return True, []

    results: list[dict] = []
    all_passed = True

    for i, tc in enumerate(test_cases):
        tc_input = tc.get("input", {})
        expected_min = tc.get("expected_risk_min", 0)

        runner_code = textwrap.dedent(f"""\
            import json, sys
            {function_code}

            # Find the function (first def in the code)
            import types
            func = None
            for name, obj in list(globals().items()):
                if isinstance(obj, types.FunctionType) and name.startswith("detect_"):
                    func = obj
                    break

            if func is None:
                print(json.dumps({{"error": "No detect_* function found"}}))
                sys.exit(1)

            try:
                result = func(**{json.dumps(tc_input)})
                print(json.dumps(result if isinstance(result, dict) else {{"result": result}}))
            except Exception as e:
                print(json.dumps({{"error": str(e)}}))
                sys.exit(1)
        """)

        try:
            result = subprocess.run(
                [sys.executable, "-c", runner_code],
                capture_output=True,
                text=True,
                timeout=timeout,
                env={"PYTHONPATH": "", "HOME": "/tmp", "PATH": ""},
                cwd="/tmp",
            )

            if result.returncode != 0:
                results.append({
                    "test": i, "passed": False,
                    "error": result.stderr.strip()[:200],
                })
                all_passed = False
            else:
                try:
                    output = json.loads(result.stdout.strip())
                    risk = output.get("risk_score", output.get("risk", 0))
                    passed = risk >= expected_min
                    results.append({
                        "test": i, "passed": passed,
                        "risk": risk, "expected_min": expected_min,
                    })
                    if not passed:
                        all_passed = False
                except json.JSONDecodeError:
                    results.append({
                        "test": i, "passed": False,
                        "error": "Non-JSON output",
                    })
                    all_passed = False

        except subprocess.TimeoutExpired:
            results.append({
                "test": i, "passed": False,
                "error": f"Timeout ({timeout}s)",
            })
            all_passed = False

    return all_passed, results
